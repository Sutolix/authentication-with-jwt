import mongoose from 'mongoose'
import dotenv from 'dotenv'

dotenv.config()

const { DB_USER, DB_PASS, DB_HOST } = process.env

const db = mongoose.connection

mongoose.connect(
  `mongodb+srv://${DB_USER}:${DB_PASS}@${DB_HOST}/auth?retryWrites=true&w=majority`,
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true
  }
);

db.on('error', () => console.error('connection error:'))
db.once('open', () => console.log('database connected'))