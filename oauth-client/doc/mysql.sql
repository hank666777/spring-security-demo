-- drop table if exist user;
create table user
(
    id               int primary key,
    user_id          varchar(10) not null,
    username         nvarchar(30) not null,
    email            varchar(100) default '',
    phone            varchar(20)  default '',

    logic_delete     char(1)      default '0' comment '0:use 1:delete',
    enable           char(1)      default '0' comment '0:disable 1:enable',
    version          int          default 0,
    create_time      datetime     default now(),
    create_by        varchar(10) comment 'userid',
    last_update_time datetime,
    last_update_by   varchar(10) comment 'userid'
    constraints pk (userid)
) comment 'user';

insert into user (user_id, username, email, pehone, logic_delete, enable, create_by, last_update_by)
values ('admin', 'ADMIN', 'admin@example.com', '0987654321', '0', '1', 'SYSTEM', 'SYSTEM');

-- drop table if exist department;
create table department
(
    id               int primary key,
    dept_id          varchar(10) not null,
    dept_name        nvarchar(30) not null,
    level            int         not null comment '10 20 40 60 80 100 200',

    version          int      default 0,
    create_time      datetime default now(),
    create_by        varchar(10) comment 'userid',
    last_update_time datetime,
    last_update_by   varchar(10) comment 'userid'
    constraints pk (dept_id)
) comment 'department'

insert into department (dept_id, dept_name, create_by, last_update_by)
    value ('IT100', 'IT', 'SYSTEM', 'SYSTEM');

-- drop table if exist role;
create table role
(
    id               int primary key,
    role_id          varchar(10) not null,
    role_name        varchar(100) default '',

    logic_delete     char(1)      default '0' comment '0:use 1:delete',
    enable           char(1)      default '0' comment '0:disable 1:enable',
    version          int          default 0,
    create_time      datetime     default now(),
    create_by        varchar(10) comment 'userid',
    last_update_time datetime,
    last_update_by   varchar(10) comment 'userid'
    constraints pk (userid)
);
insert into role (role_id, role_name, create_by, last_update_time, last_update_by)
values ('manager', 'manager', 'SYSTEM', '2025-01-01T00:00:00', 'SYSTEM'),
values ('employee', 'employee', 'SYSTEM', '2025-01-01T00:00:00', 'SYSTEM');


-- drop table if exist user_role;
create table user_role
(
    id          int primary key,
    user_id     varchar(10) not null,
    role_id     varchar(10) not null,

    create_time datetime default now(),
    create_by   varchar(10) comment 'userid',
    constraints pk (userid, role_id)
);

insert into user_role (user_id, role_id)
values ('admin', 'manager'),
       ('admin', 'employee');
