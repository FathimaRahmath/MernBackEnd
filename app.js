const express = require('express')
const morgan = require('morgan')
require('dotenv').config();
const cors = require('cors')


const bodyParser = require('body-parser');

// const config = require('./Config/config');
const authRoutes = require('./Routes/authRoutes');
const employeeRoutes = require('./Routes/employeeRoutes');

// const userRoute=require('./Routes/userRoutes')
// const postroute = require('./Routes/postRoutes')

const PORT = process.env.PORT;
const db = require('./DB/connection');
const app = express();

app.use(morgan('dev'));

// Middleware
app.use(cors());
app.use(bodyParser.json());


// Routes
app.use('/api/employees', employeeRoutes);
// app.use('/api', userRoute)
// app.use('/api', postroute)
// Routes

app.use('/api', authRoutes); // Use authRoutes



app.listen(PORT, () => {
    console.log(`Port ${PORT} is up and running`)
})