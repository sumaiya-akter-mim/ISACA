-- Sample SQL dump containing common hash formats for audit testing
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL,
  password TEXT NOT NULL
);

INSERT INTO users (id, username, password) VALUES
  (1, 'admin', '21232f297a57a5a743894a0e4a801fc3'),
  (2, 'bob', 'da4b9237bacccdf19c0760cab7aec4a8359010b0'),
  (3, 'alice', '$2b$12$C6UzMDM.H6dfI/f/IKxGhuYb8RZ8a6Z5S9YLeuYf1b9QZ/ZuQn66.'),
  (4, 'charlie', '$argon2id$v=19$m=65536,t=3,p=4$Wm9tYmllU2FsdA$K1bPq8Cq3ZJXzRys3vYUvA');