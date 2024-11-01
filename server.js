const mongoose = require('mongoose');
const dotenv = require('dotenv');

process.on('uncoughtException', (err) => {
  console.log('UNCOUGHT EXCEOTION  Shuting down ...');

  console.log(err.name, err.message);

  process.exit();
});

dotenv.config({ path: './config.env' });

const app = require('./app.js');

const DB = process.env.DATABASE.replace('<PASSWORD>', process.env.DB_PASSWORD);

const localDB = process.env.DATABASE_LOCAL;

mongoose.connect(localDB).then((conn) => {
  console.log('DB connection successful!');
});

const port = process.env.PORT || 3000;
const server = app.listen(port, () => {
  console.log(`App running on port ${port}...`);
});

process.on('unhandeledRejection', (err) => {
  console.log('UNHANDELED REJECTION  💥 Shuting down.... ');
  console.log(err.name, err.message);

  server.close(() => {
    process.exit();
  });
});
