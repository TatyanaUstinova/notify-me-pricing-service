import uuid

from src.common.database import Database
import src.models.stores.constants as StoreConstants
import src.models.stores.errors as StoreErrors


class Store(object):

    def __init__(self, name, url_prefix, tag_name, query, _id=None):
        self.name = name
        self.url_prefix = url_prefix
        self.tag_name = tag_name
        self.query = query
        self._id = uuid.uuid4().hex if _id is None else _id

    def __repr__(self):
        return "<Store {}>".format(self.name)

    def make_json(self):
        json_data = {
            "_id": self._id,
            "name": self.name,
            "url_prefix": self.url_prefix,
            "tag_name": self.tag_name,
            "query": self.query
        }
        return json_data

    @classmethod
    def get_by_id(cls, id):
        return cls(**Database.find_one(StoreConstants.COLLECTION, {"_id": id}))

    def to_mongo(self):
        Database.update(StoreConstants.COLLECTION, {"_id": self._id}, self.make_json())

    @classmethod
    def get_by_name(cls, store_name):
        return cls(**Database.find_one(StoreConstants.COLLECTION, {"name": store_name}))

    @classmethod
    def get_by_url_prefix(cls, url_prefix):
        return cls(**Database.find_one(StoreConstants.COLLECTION, {"url_prefix": {"$regex": "^{}".format(url_prefix)}}))

    @classmethod
    def find_by_url(cls, url):
        """
        Returns a store from a url like
        "http://www.mvideo.ru/products/mysh-besprovodnaya-logitech-m280-black-910-004287-50045850"
        :param url: the item's URL
        :return: a Store, or raises StoreNotFoundException if no store matches the URL
        """
        for i in range(len(url) - 1, -1, -1):
            try:
                store = cls.get_by_url_prefix(url[:i])
                if store:
                    return store
            except:
                pass
        raise StoreErrors("No store found.")

    @classmethod
    def all(cls):
        return [cls(**elem) for elem in Database.find(StoreConstants.COLLECTION, {})]

    def delete(self):
        Database.remove(StoreConstants.COLLECTION, {"_id": self._id})
