const express = require("express")
const app = express()

const PORT = process.env.PORT || 3000;

app.use("/assets",express.static(__dirname+'/static'))
app.set('view engine','ejs')
app.get('/',(req,res)=>{
    res.render("index")
})


app.listen(PORT,()=>{
    console.log(`Server running on PORT ${PORT}`)
})
