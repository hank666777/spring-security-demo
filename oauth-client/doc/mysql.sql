-- drop table if exist user;
create table user
(
    id               int primary key,
    user_id          varchar(10) not null,
    username         varchar(30) not null,
    pwd_hash         varchar(100) default '' comment '密碼 hash',
    dept_id          varchar(10) not null,
    email            varchar(100) default '',
    phone            varchar(20)  default '',

    logic_delete     char(1)      default '0' comment '0:use 1:delete',
    enable           char(1)      default '0:disable 1:enable',
    version          int          default 0,
    create_time      datetime     default now(),
    create_by        varchar(10) comment 'userid',
    last_update_time datetime,
    last_update_by   varchar(10) comment 'userid',
    constraints user_pk unique (userid)
) comment 'user';
insert into user (user_id, username, pwd_hash, dept_id, email, phone, logic_delete, enable, version, create_time,
                  create_by)
values ('IT_ADMIN', '管理員', '$2a$12$heEnv0UtCqlIlzLvVX1lB.Gy5UYno2WcDOu0pQF3GvosTlXWynnOW', '', '', '', '0', '1', 0,
        now(), 'IT_ADMIN'),
       ('USER_A', '使用者A', '$2a$12$heEnv0UtCqlIlzLvVX1lB.Gy5UYno2WcDOu0pQF3GvosTlXWynnOW', '', '', '', '0', '1', 0,
        now(), 'IT_ADMIN');

-- drop table if exist dept;
create table dept
(
    id               int primary key,
    dept_id          varchar(10) not null,
    dept_name        varchar(100) default '' comment '名稱',
    parent_dept_id   varchar(10)  default '上級部門 id，指向 dept_id',

    version          int      default 0,
    create_time      datetime default now(),
    create_by        varchar(10) comment 'userid',
    last_update_time datetime,
    last_update_by   varchar(10) comment 'userid',
    constraints      user_pk unique (userid)
) comment '部門';

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
    last_update_by   varchar(10) comment 'userid',
    constraints role_pk unique (role_id)
) comment '角色';
insert into role (role_id, role_name, logic_delete, enable, version, create_time, create_by)
values ('ADMIN', '管理員', '0', '1', 0, now(), 'IT_ADMIN'),
       ('USER', '使用者', '0', '1', 0, now(), 'IT_ADMIN');

-- drop table if exist user_role;
create table user_role
(
    id          int primary key,
    user_id     varchar(10) not null,
    role_id     varchar(10) not null,

    create_time datetime default now(),
    create_by   varchar(10) comment 'userid',
    constraints user_role_pk unique (user_id, role_id)
) comment '使用者角色關聯';
insert into user_role (id, user_id, role_id, create_time, create_by)
values (0, 'IT_ADMIN', 'ADMIN', now(), 'IT_ADMIN'),
       (1, 'USER_A', 'USER', now(), 'IT_ADMIN');

-- drop table if exist menu;
create table menu
(
    id               int primary key,
    menu_id          varchar(10) not null,
    menu_name        varchar(255) default '' comment '名稱',
    menu_parent_id   varchar(10)  default '' comment '上級目錄 id，指向 menu_id',
    menu_sort        int          default 0 comment '選單順序',
    menu_uri         varchar(100) default '' comment '資源路徑',
    http_method      varchar(50)  default '' comment '允許的 HTTP 方法（逗號分隔，如 GET,POST 或 * 表示全部）',
    is_pattern       char(1)      DEFAULT '0' COMMENT '是否為通配符路徑（0: 精確匹配, 1: 通配符）',
    enable           char(1)      default '0:disable 1:enable',
    version          int          default 0,
    create_time      datetime     default now(),
    create_by        varchar(10) comment 'userid',
    last_update_time datetime,
    last_update_by   varchar(10) comment 'userid',
    constraints      menu_pk unique (menu_id)
) comment '選單目錄';

-- drop table if exist menu_role;
create table menu_role
(
    id          int primary key,
    menu_id     varchar(10) not null,
    role_id     varchar(10) not null,

    create_time datetime default now(),
    create_by   varchar(10) comment 'userid',
    constraints menu_role_pk unique (menu_id, role_id)
) comment '選單角色關聯';

