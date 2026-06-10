const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcrypt");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static(__dirname));

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

let onlineUsers = {};

io.on("connection", (socket) => {

  console.log("user connected");

  socket.on("register", async (data) => {

    const username = data.username.trim();
    const password = data.password;

    const hash = await bcrypt.hash(password, 10);

    const { error } = await supabase
      .from("users")
      .insert({
        username,
        password_hash: hash
      });

    if (error) {
      socket.emit("register_result", {
        success: false,
        message: "Gebruikersnaam bestaat al"
      });
      return;
    }

    socket.emit("register_result", {
      success: true,
      message: "Account gemaakt"
    });

  });

  socket.on("login", async (data) => {

    const username = data.username.trim();
    const password = data.password;

    const { data: users } = await supabase
      .from("users")
      .select("*")
      .eq("username", username);

    if (!users || users.length === 0) {
      socket.emit("login_result", {
        success: false,
        message: "Gebruiker niet gevonden"
      });
      return;
    }

    const user = users[0];

    const ok = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!ok) {
      socket.emit("login_result", {
        success: false,
        message: "Verkeerd wachtwoord"
      });
      return;
    }

    onlineUsers[username] = socket.id;

    socket.emit("login_result", {
      success: true,
      username
    });

  });

  socket.on("disconnect", () => {

    for (const username in onlineUsers) {
      if (onlineUsers[username] === socket.id) {
        delete onlineUsers[username];
      }
    }

  });

});

server.listen(process.env.PORT || 3000, () => {
  console.log("server running");
});
