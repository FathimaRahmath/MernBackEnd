const mongoose = require('mongoose');
mongoose.connect(process.env.mongodb_url)
    .then(() => {
        console.log('DB Connected');
    })
    .catch((error) => {
        console.error('Connection Error:', error);
    });
