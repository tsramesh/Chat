-- Create Tables
CREATE TABLE chat_groups (
    group_id VARCHAR2(256) PRIMARY KEY,
    group_name VARCHAR2(256),
    creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    update_date TIMESTAMP
);

CREATE TABLE chat_users (
    user_id NUMBER PRIMARY KEY,
    username VARCHAR2(256),
    creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    update_date TIMESTAMP
);

CREATE TABLE chat_group_members (
    group_id VARCHAR2(256),
    user_id NUMBER,
    creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    update_date TIMESTAMP,
    FOREIGN KEY (group_id) REFERENCES chat_groups(group_id),
    FOREIGN KEY (user_id) REFERENCES chat_users(user_id),
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE chat_messages (
    message_id NUMBER PRIMARY KEY,
    group_id VARCHAR2(256),
    content CLOB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    update_date TIMESTAMP,
    FOREIGN KEY (group_id) REFERENCES chat_groups(group_id)
);

CREATE TABLE chat_message_read_status (
    message_id NUMBER,
    user_id NUMBER,
    read_status CHAR(1) CHECK (read_status IN ('Y', 'N')),
    read_timestamp TIMESTAMP,
    creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    update_date TIMESTAMP,
    PRIMARY KEY (message_id, user_id),
    FOREIGN KEY (message_id) REFERENCES chat_messages(message_id),
    FOREIGN KEY (user_id) REFERENCES chat_users(user_id)
);

-- Create Sequences
CREATE SEQUENCE chat_user_seq
    START WITH 1
    INCREMENT BY 1
    NOCACHE
    NOCYCLE;

CREATE SEQUENCE chat_message_seq
    START WITH 1
    INCREMENT BY 1
    NOCACHE
    NOCYCLE;

CREATE SEQUENCE chat_group_seq
    START WITH 1
    INCREMENT BY 1
    NOCACHE
    NOCYCLE;

-- Create Triggers
CREATE OR REPLACE TRIGGER chat_users_bir
BEFORE INSERT ON chat_users
FOR EACH ROW
BEGIN
    :NEW.user_id := chat_user_seq.NEXTVAL;
    IF :NEW.username IS NULL THEN
        :NEW.username := 'User-' || :NEW.user_id;
    END IF;
    :NEW.creation_date := CURRENT_TIMESTAMP;
END;
/

CREATE OR REPLACE TRIGGER chat_messages_bir
BEFORE INSERT ON chat_messages
FOR EACH ROW
BEGIN
    :NEW.message_id := chat_message_seq.NEXTVAL;
    :NEW.creation_date := CURRENT_TIMESTAMP;
END;
/

CREATE OR REPLACE TRIGGER chat_messages_bur
BEFORE UPDATE ON chat_messages
FOR EACH ROW
BEGIN
    :NEW.update_date := CURRENT_TIMESTAMP;
END;
/

CREATE OR REPLACE TRIGGER chat_groups_bir
BEFORE INSERT ON chat_groups
FOR EACH ROW
BEGIN
    :NEW.group_id := chat_group_seq.NEXTVAL;
    IF :NEW.group_name IS NULL THEN
        :NEW.group_name := 'Group-' || :NEW.group_id;
    END IF;
    :NEW.creation_date := CURRENT_TIMESTAMP;
END;
/

CREATE OR REPLACE TRIGGER chat_group_members_bir
BEFORE INSERT ON chat_group_members
FOR EACH ROW
BEGIN
    :NEW.creation_date := CURRENT_TIMESTAMP;
END;
/

CREATE OR REPLACE TRIGGER chat_group_members_bur
BEFORE UPDATE ON chat_group_members
FOR EACH ROW
BEGIN
    :NEW.update_date := CURRENT_TIMESTAMP;
END;
/

CREATE OR REPLACE TRIGGER chat_message_read_status_bir
BEFORE INSERT ON chat_message_read_status
FOR EACH ROW
BEGIN
    :NEW.creation_date := CURRENT_TIMESTAMP;
END;
/

CREATE OR REPLACE TRIGGER chat_message_read_status_bur
BEFORE UPDATE ON chat_message_read_status
FOR EACH ROW
BEGIN
    :NEW.update_date := CURRENT_TIMESTAMP;
END;
/
