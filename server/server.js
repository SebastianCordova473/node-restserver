require('./config/config');
const options = {
    keepAlive: 1,
    useUnifiedTopology: true,
    useNewUrlParser: true,
    useCreateIndex: true
};
const express = require('express');
const mongoose = require('mongoose');


const app = express();

const bodyParser = require('body-parser');

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }));

// parse application/json
app.use(bodyParser.json());


// configuracion global de rutas
app.use(require('./routes/index'));



mongoose.connect(process.env.URLDB, options,(err, res) => {

    if (err) throw err;

    console.log('Base de datos ONLINE');

});



app.listen(process.env.PORT, () => {
    console.log('Escuchando puerto: ', process.env.PORT);
});