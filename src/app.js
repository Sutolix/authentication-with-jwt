import './database/connection.js'
import { UserModel } from './models/user.js';
import * as jwt from './authentication/jwt.js'

import express from 'express';

const app = express()

//Middlewares for POST requests
app.use(express.json()) // accepts data from objects
app.use(express.urlencoded({extended: false})) // accepts data from forms


const authMiddleware = async (req, res, next) => {
  const [ hashType,token ] = req.headers.authorization.split(' ')

  try {
    const paylod = await jwt.verify(token)

    const user = await UserModel.findById(paylod.userID)

    if(!user) {
      return res.send(401)
    }

    req.auth = user // to recupe the logged user

    next()
    
  } catch (errr) {
    res.send(errr).status(401)
  }
}

app.post('/signup', async (req, res) => {
  
  try {
    const result = await UserModel.create(req.body)

    const {password, ...user} = result.toObject() // remove password of return

    const token = jwt.sign({userID: user.id})

    res.send({ user, token })
  } catch (err) {
    res.status(400).send(err)
  }

});

app.get('/login', async (req, res) => {
  const [ hashType, hash ] = req.headers.authorization.split(' ')

  const [ email, password ] = Buffer.from(hash, 'base64')
    .toString()
    .split(':')

  try {

    const user = await UserModel.findOne({email, password})

    if(!user) {
      return res.send(401)
    }

    const token = jwt.sign({userID: user.id})

    res.send({ user, token })

  } catch (err) {
    res.status(err)
  }
})

app.get('/users', authMiddleware , async (req, res) => {
  try {
    const users = await UserModel.find()

    res.send(users)
    
  } catch (err) {
    res.send(err)
  }
})

app.get('/me', authMiddleware, (req, res) => {
  res.send(req.auth)
})

app.listen(3333);