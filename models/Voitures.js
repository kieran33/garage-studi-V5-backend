const mongoose = require("mongoose");

const SchemaVoiture = new mongoose.Schema({
    marque: String,
    nombreVues: Number
})

const VoitureModel = mongoose.model("voitures_populaires", SchemaVoiture);
module.exports = VoitureModel;