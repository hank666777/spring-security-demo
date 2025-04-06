-- drop table if exist user;
create table user
(
    id               int primary key,
    user_id          varchar(10) not null,
    username         varchar(30) not null,
    email            varchar(100) default '',
    phone            varchar(20)  default '',

    logic_delete     char(1)      default '0' comment '0:use 1:delete',
    enable           char(1)      default '0:disable 1:enable',
    version          int          default 0,
    create_time      datetime     default now(),
    create_by        varchar(10) comment 'userid',
    last_update_time datetime,
    last_update_by   varchar(10) comment 'userid'
    constraints pk (userid)
) comment 'user';

-- drop table if exist role;
create table role
(
    id               int primary key,
    role_id          varchar(10) not null,
    role_name        varchar(100) default '',

    logic_delete     char(1)      default '0' comment '0:use 1:delete',
    enable           char(1)      default '0:disable 1:enable',
    version          int          default 0,
    create_time      datetime     default now(),
    create_by        varchar(10) comment 'userid',
    last_update_time datetime,
    last_update_by   varchar(10) comment 'userid'
    constraints pk (userid)
);

-- drop table if exist user_role;
create table user_role
(
    id          int primary key,
    user_id     varchar(10) not null,
    role_id     varchar(10) not null,

    create_time datetime default now(),
    create_by   varchar(10) comment 'userid',
    constraints pk (userid,role_id)
);