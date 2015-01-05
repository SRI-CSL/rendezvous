use onionfactory;

DROP TABLE if exists server;
DROP TABLE if exists key_pair;
DROP TABLE if exists onion;
DROP TABLE if exists server_onion_map;

CREATE TABLE server (
    server_id  bigint not null auto_increment,
    key_pair_id bigint not null,
    create_time timestamp not null default CURRENT_TIMESTAMP,
    last_time datetime not null,
    requests bigint not null default 0,    
    PRIMARY KEY (server_id)
) ENGINE = InnoDB
  Character Set = utf8;

CREATE TABLE key_pair (
  key_pair_id  bigint not null auto_increment,
  public_key  varchar(512) not null,
  Qid varchar(512) not null,
  Did varchar(512) not null,
  create_time timestamp not null default CURRENT_TIMESTAMP,
  PRIMARY KEY (key_pair_id)
) ENGINE = InnoDB
  Character Set = utf8;

CREATE TABLE onion (
   onion_id bigint not null auto_increment,
   onion_size bigint not null,
   pow_password varchar(64) not null,   
   captcha_password varchar(64) not null,        
   nep varchar(1024) not null,       
   create_time timestamp not null default CURRENT_TIMESTAMP,
   PRIMARY KEY (onion_id)
) ENGINE = InnoDB
  Character Set = utf8;

CREATE TABLE server_onion_map (
  server_onion_map_id bigint not null auto_increment,
  server_id bigint,
  onion_id bigint,
  create_time timestamp not null default CURRENT_TIMESTAMP,
  PRIMARY KEY (server_onion_map_id)
) ENGINE = InnoDB
  Character Set = utf8;
  




