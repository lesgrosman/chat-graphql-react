const bcrypt = require('bcryptjs')
const { AuthenticationError, UserInputError } = require('apollo-server')
const jwt = require('jsonwebtoken')
const { Op } = require('sequelize')


const { User } = require('../models')
const { JWT_SECRET } = require('../config/env.json')

module.exports = {
  Query: {
    getUsers: async (parent, args, context) => {
      try {
        let user
        if (context.req && context.req.headers.authorization) {
          const token = context.req.headers.authorization.split('Bearer ')[1]
          jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
            if (err) {
              throw new AuthenticationError('Unauthenticated')
            }
            user = decodedToken
          })
        }
        const users = await User.findAll({ 
          where: { username: { [Op.ne]: user.username } }
         })
        return users
      } catch(err) {
        console.log(err)
        throw err
      }
    },
    login: async (parent, args) => {
      const { username, password } = args
      const errors = {}
      try {
        if (username.trim() === '') errors.username = 'username must not be empty'
        if (password.trim() === '') errors.password = 'password must not be empty'

        if (Object.keys(errors).length > 0) {
          throw new UserInputError('user not found', { errors })
        }

        const user = await User.findOne({ where: { username } })

        if (!user) {
          errors.username = 'user not found'
          throw new UserInputError('user not found', { errors })
        }

        const correctPassword = await bcrypt.compare(password, user.password)

        if (!correctPassword) {
          errors.password = 'password is not correct'
          throw new UserInputError('password is incorrect', { errors })
        }

        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });

        return {
          ...user.toJSON(),
          createdAt: user.createdAt.toISOString(),
          token
        }

      } catch(err) {
        console.log(err)
        throw err 
      }
    }

  },
  Mutation: {
    register: async (parent, args, context, info) => {
      let { username, email, password, confirmPassword } = args
      const errors = {}
      try {
        // Validate input data
        if (username.trim() === '') errors.username = 'username must not be empty'
        if (email.trim() === '') errors.email = 'email must not be empty'
        if (password.trim() === '') errors.password = 'password must not be empty'
        if (confirmPassword.trim() === '') errors.confirmPassword = 'repeat password must not be empty'
        if (password !== confirmPassword) errors.confirmPassword = 'passwords must match'

        if (Object.keys(errors).length > 0) {
          throw errors
        }

        // Hash password
        password = await bcrypt.hash(password, 6)

        // Create user
        const user = await User.create({
          username,
          email, 
          password
        })

        // Return user
        return user
      } catch(err) {
        console.log(err)
        if (err.name === 'SequelizeUniqueConstraintError') {
          const error = err.parent.constraint.slice(err.parent.constraint.indexOf(`_`) + 1, err.parent.constraint.lastIndexOf(`_`))
          errors[error] = `${error} is already taken`
        } else if (err.name === 'SequelizeValidationError') {
          err.errors.forEach(e => errors[e.path] = e.message)
        }
        throw new UserInputError('Bad Input', { errors })
      }
    }
  }
}
