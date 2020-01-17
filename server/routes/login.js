const express = require("express");

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const Usuario = require("../models/usuario");

const app = express();
const {OAuth2Client} = require("google-auth-library");
const client = new OAuth2Client(process.env.CLIENT_ID);

app.post("/login", (req, res) => {
  let body = req.body;

  Usuario.findOne({email: body.email}, (err, usuarioDB) => {
    if (err) {
      return res.status(500).json({
        ok: false,
        err
      });
    }

    if (!usuarioDB) {
      return res.status(400).json({
        ok: false,
        err: {
          message: "(Usuario) o contraseña incorrectos"
        }
      });
    }

    if (!bcrypt.compareSync(body.password, usuarioDB.password)) {
      return res.status(400).json({
        ok: false,
        err: {
          message: "Usuario o (contraseña) incorrectos"
        }
      });
    }

    let token = jwt.sign(
      {
        usuario: usuarioDB
      },
      process.env.SEED,
      {expiresIn: process.env.CADUCIDAD_TOKEN}
    );

    res.json({
      ok: true,
      usuario: usuarioDB,
      token
    });
  });
});

//configuracion de google

async function verify(token) {
  const ticket = await client.verifyIdToken({
    idToken: token,
    audience: process.env.CLIENT_ID // Specify the CLIENT_ID of the app that accesses the backend
    // Or, if multiple clients access the backend:
    //[CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3]
  });
  const payload = ticket.getPayload();
  console.log(payload.name);
  console.log(payload.email);
  console.log(payload.picture);
  return {
    name: payload.name,
    email: payload.email,
    img: payload.picture,
    google: true
  };
}
app.post("/google", async (req, res) => {
  let token = req.body.idtoken;
  let googleUser = await verify(token).catch(e => {
    return res.status.json({
      err: e
    });
  });

  // Iniciar la busqueda del usuario por el email
  Usuario.findOne({email: googleUser.email}, (err, usuarioDB) => {
    // Hay errores?
    if (err) {
      return res.status(500).json({
        ok: false,
        err
      });
    }
    // existe el usuario en la base de datos?
    if (usuarioDB) {
      // El usuario ya se ha autenticado con credenciales normales?
      if (usuarioDB.google === false) {
        return res.status(500).json({
          ok: false,
          err: {
            message: "Debe usar su autenticación normal"
          }
        });
      }
      // El usuario no se ha autenticado con credenciales normnales
      // Procedemos a renovar su token
      else {
        let token = jwt.sign(
          {
            usuario: usuarioDB
          },
          process.env.SEED,
          {expiresIn: process.env.CADUCIDAD_TOKEN}
        );

        return res.json({
          ok: true,
          usuario: usuarioDB,
          token
        });
      }
    }
    //El usuario no existe en la Base de datos
    else {
      // Creamos objeto usuario
      let usuario = new Usuario();
      // Asignamos las variables a la base de datos con la informacion obtenida en la API de Google Sign In
      usuario.nombre = googleUser.name;
      usuario.email = googleUser.email;
      usuario.img = googleUser.img;
      usuario.google = true;
      usuario.password = ":)";
      // Guardamos el usuario a la base de datos
      usuario.save((err, usuarioDB) => {
        // Hay errores?
        if (err) {
          return res.status(500).json({
            ok: false,
            err
          });
        }
        //Generamos el token
        let token = jwt.sign(
          {
            usuario: usuarioDB
          },
          process.env.SEED,
          {expiresIn: process.env.CADUCIDAD_TOKEN}
        );

        //Mandamos la respuesta
        return res.json({
          ok: true,
          usuario: usuarioDB,
          token
        });
      });
    }
  });

  // res.json({
  //     usuario: googleUser
  // });
});

module.exports = app;
