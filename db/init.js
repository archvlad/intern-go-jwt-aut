db = db.getSiblingDB('go-jwt-auth');

db.users.insertMany([{ guid: '1' }, { guid: '2' }]);
