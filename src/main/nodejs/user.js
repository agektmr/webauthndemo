'use strict';
const Datastore = require('@google-cloud/datastore');

class UserService {
  constructor() {
    this.datastore = Datastore();
  }
  getCurrentUser() {

  }
  addNewUser() {

  }
}

class User {
  constructor() {

  }
  getUserId() {

  }
  getNickname() {

  }
}

module.exports.userService = new UserService();
