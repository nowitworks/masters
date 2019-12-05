const path = require("path")
const express = require("express")
const cors = require("cors")

const app = express()

const hostname = "127.0.0.1";
const port = 3500;

// CORS ------------------------------------------------
app.use(cors())

// -----------------------------------------------------

app.use("/", express.static(path.join(__dirname, "files")))

app.listen(port, (err) => {
  if (err) {
    return console.log("something bad happened", err)
  }

  console.log(`server is listening on http://${hostname}:${port}/`)
})
