CREATE DATABASE onionfactory;
CREATE USER onionserver@localhost IDENTIFIED BY 'onionserver4mysql';

GRANT select, insert, update, delete, execute, lock tables on onionfactory.* to onionserver@localhost identified by 'onionserver4mysql';

