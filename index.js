"use strict";
const express = require("express");
const morgan = require("morgan");
const sequelize = require("./models").sequelize;
const routes = require("./routes");
const cors = require("cors");
const app = express();
app.use(cors());
app.use(morgan('dev'));
app.use(express.json());
app.use("/api", routes);
app.get("/", (req, res) => {
  res.json({
    message: "Welcome to the project!",
  });
});

// send 404 if no other route matched
app.use((req, res) => {
  res.status(404).json({
    message: "Route Not Found",
  });
});

// setup a global error handler
app.use((err, req, res, next) => {
  if (enableGlobalErrorLogging) {
    console.error(`Global error handler: ${JSON.stringify(err.stack)}`);
  }

  res.status(err.status || 500).json({
    message: err.message,
    error: {},
  });
});

// set our port

// start listening on our port

app.set("port", process.env.PORT || 5000);

const server = app.listen(app.get("port"), () => {
  console.log(`Express server is listening on port ${server.address().port}`);
});

sequelize.sync(function () {
  if (sequelize.authentificate()) {
    console.log("database connection established successfully ");
  } else {
    console.log("database not connected");
  }
});
