require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// Config JSON response
app.use(express.json());

// Models
const User = require("./models/User");

// Open Route - Public Route
app.get("/", (req, res) => {
  res.status(200).json({ message: "Bem vindo a nossa API!" });
});

function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split("")[1];

  if (!token) {
    return res.status(401).json({ message: "Acesso negado!" });
  }
}

// Private Route
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  //check if user exists
  const user = await User.findById(id, "-password");

  if (!user) {
    return res.status(404).json({ message: "Usuário não encontrado!" });
  }

  res.status(200).json({ user });

  try {
    const secret = process.env.SECRET;

    jwt.verify(token, secret);

    next();
  } catch (error) {
    res.status(400).json({ message: "Token inválido!" });
  }
});

// Register User
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpassword } = req.body;

  // validations
  if (!name) {
    return res.status(422).json({ message: "O nome é obrigatório!" });
  }
  if (!email) {
    return res.status(422).json({ message: "O email é obrigatório!" });
  }
  if (!password) {
    return res.status(422).json({ message: "A password é obrigatória!" });
  }

  if (password !== confirmpassword) {
    return res.status(422).json({ message: "As senhas não conferem!" });
  }

  //check if user exists
  const userExists = await User.findOne({ email: email });

  if (userExists) {
    return res.status(422).json({ message: "Email já utilizado!" });
  }

  //create password
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  //create user
  const user = new User({
    name,
    email,
    password: passwordHash,
  });

  try {
    await user.save();

    res.status(201).json({ message: "Usuário criado com sucesso!" });
  } catch (error) {
    console.log(error);

    return res.status(500).json({
      message:
        "Aconteceu um erro inesperado no servidor, tente novamente mais tarde!",
    });
  }
});

// Login User
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  //validations
  if (!email) {
    return res.status(422).json({ message: "O email é obrigatório!" });
  }
  if (!password) {
    return res.status(422).json({ message: "A senha é obrigatória!" });
  }

  //check if user exists
  const user = await User.findOne({ email: email });

  if (!user) {
    return res.status(404).json({ message: "Usuário não encontrado!" });
  }

  //check if password match
  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return res.status(422).json({ message: "Senha inválida!" });
  }

  try {
    const secret = process.env.SECRET;

    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );

    res
      .status(200)
      .json({ message: "Autenticação realizada com sucesso!", token });
  } catch (error) {
    console.log(error);

    return res.status(500).json({
      message:
        "Aconteceu um erro inesperado no servidor, tente novamente mais tarde!",
    });
  }
});

// Credencials
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASSWORD;

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@authnodejwtcluster.8fdkq.mongodb.net/authJWTDatabase?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(3000);
    console.log("Conectou ao banco!");
  })
  .catch((error) => console.log(error));
