'use strict';

module.exports = {
  up: (queryInterface, Sequelize) => {
    const now = new Date().toLocaleString({ timeZone: 'Asia/Tokyo' });
    return queryInterface.bulkInsert('Users', [
      { id:1, name: '太郎',  email: 'taro@example.com', password: 'taro-password', createdAt: now, updatedAt: now},
      { id:2, name: '次郎',  email: 'jiro@example.com', password: 'jiro-password', createdAt: now, updatedAt: now},
      { id:3, name: '三郎',  email: 'saburo@example.com', password: 'saburo-password', createdAt: now, updatedAt: now},
      { id:4, name: '四郎',  email: 'shiro@example.com', password: 'shiro-password', createdAt: now, updatedAt: now},
      { id:5, name: '五郎',  email: 'goro@example.com', password: 'goro-password', createdAt: now, updatedAt: now},
    ], {});
  },

  down: (queryInterface, Sequelize) => {
    return queryInterface.bulkDelete('Users', null, {});
  }
};