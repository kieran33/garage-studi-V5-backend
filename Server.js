const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcrypt');
const path = require('path');
const multer = require('multer');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const mongoose = require("mongoose");
const VoitureModel = require("./models/Voitures");

mongoose.connect(process.env.MONGO_URL);

// On initialise notre serveur
const app = express();

const port = 3002;

app.use(cors());
app.use(bodyParser.json());

app.get("/vues-voitures", (req, res) => {
    VoitureModel.find()
        .then(voitures => res.json(voitures))
        .catch(voitures => res.json(voitures))
});

app.put("/augmenter-vues-voitures", (req, res) => {
    const { marqueVoiture } = req.body;

    console.log('marque voiture', marqueVoiture)

    if (marqueVoiture !== undefined) {
        VoitureModel.findOneAndUpdate(
            { marque: marqueVoiture },
            { $inc: { nombreVues: 1 } })
            .then(voitures => res.json(voitures))
            .catch(voitures => res.json(voitures))
    }
});

app.post("/ajout-voitures-vues", (req, res) => {
    const { marqueVoiture } = req.body;

    VoitureModel.insertMany(
        { marque: marqueVoiture },
        { nombreVues: 0 })
        .then(voitures => res.json(voitures))
        .catch(voitures => res.json(voitures))
});

app.delete("/supprimer-voitures-vues/:marqueVoiture", (req, res) => {
    const { marqueVoiture } = req.params;

    VoitureModel.findOneAndDelete({ marque: marqueVoiture })
        .then(voitures => res.json(voitures))
        .catch(voitures => res.json(voitures))
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "default-src 'self'; img-src 'self' http://localhost:3000;");
    return next();
});

const uploadDirectory = path.join(__dirname, 'uploads');

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDirectory);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const cleanedFileName = `image-${uniqueSuffix}.${file.originalname.replace(/[^a-zA-Z0-9.]/g, "_")}`;
        cb(null, cleanedFileName);
    }
});

const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith("image")) {
        cb(null, true);
    } else {
        cb(new Error("Seuls les fichiers image sont autorisés."), false);
    }
};

const upload = multer({ storage: storage, fileFilter: fileFilter });

let db;

if (process.env.JAWSDB_URL) {
    db = mysql.createConnection(process.env.JAWSDB_URL)
    console.log('je suis dans if jawsdb', process.env.JAWSDB_URL)
} else {
    console.log('je suis dans else jawsdb donc en local')
    db = mysql.createConnection({
        host: 'localhost',
        user: 'root', // remplacez par votre utilisateur
        password: '', // ou root1234 remplacez par votre mot de passe
        database: 'garage' // remplacez par le nom de votre base de données
        // Paramètres de connexion MySQL
    });
}

//Connectez vous à MySQL
db.connect(err => {
    if (err) throw err;
    console.log('Connecté à la base de données MySQL');

    const createEmployesTable = `
    CREATE TABLE IF NOT EXISTS employes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(255) NOT NULL
    )`;

    const createServicesTable = `
        CREATE TABLE IF NOT EXISTS services (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            content TEXT NOT NULL,
            image VARCHAR(255)
        )`;

    const createVoituresTable = `
        CREATE TABLE IF NOT EXISTS voitures (
            id INT AUTO_INCREMENT PRIMARY KEY,
            brand VARCHAR(255) NOT NULL,
            km INT(50) NOT NULL,
            price INT(50) NOT NULL,
            yearsCirculation INT(50) NOT NULL,
            image VARCHAR(255)
        )`;

    const createAvisNonVerifTable = `
        CREATE TABLE IF NOT EXISTS avisnonverif (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            message VARCHAR(255) NOT NULL,
            note INT (5) NOT NULL
        )`;

    const createAvisVerifTable = `
        CREATE TABLE IF NOT EXISTS avisverif (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            message VARCHAR(255) NOT NULL,
            note INT (5) NOT NULL
        )`;

    db.query(createServicesTable, err => {
        if (err) throw err;
        console.log("Table 'services' prête");
    });

    db.query(createVoituresTable, err => {
        if (err) throw err;
        console.log("Table 'voitures' prête");
    });

    db.query(createEmployesTable, err => {
        if (err) throw err;
        console.log("Table 'employes' prête");
    });

    db.query(createAvisNonVerifTable, err => {
        if (err) throw err;
        console.log("Table 'avisnonverif' prête");
    });

    db.query(createAvisVerifTable, err => {
        if (err) throw err;
        console.log("Table 'avisverif' prête");
    });
});

app.post('/create-employe', (req, res) => {
    const { email, password, role } = req.body;

    const saltRounds = 8;
    bcrypt.hash(password, saltRounds, function (err, hash) {
        if (err) {
            return res.status(500).send('Erreur lors du hashage')
        }

        const query = "INSERT INTO employes (email, password, role) VALUES (?, ?, ?)";

        db.query(query, [email, hash, role], (err, result) => {
            if (err) {
                res.status(500).send('Erreur lors de la création de l\'employé');
            } else {
                console.log('Employé créer avec succès');
                res.status(201).send('Employé créer avec succès');
            }
        })
    })
});

app.get("/employes", (req, res) => {
    const request = "SELECT * FROM employes"
    db.query(request, (error, result) => {
        res.send(result);
    })
});

app.get("/services", (req, res) => {
    const request = "SELECT * FROM services"
    db.query(request, (error, result) => {
        res.send(result);
    })
});

app.get('/voitures', (req, res) => {
    const request = "SELECT * FROM voitures"
    db.query(request, (error, result) => {
        res.send(result);
    })
});

app.get('/avis-non-verif', (req, res) => {
    const request = "SELECT * FROM avisnonverif"
    db.query(request, (error, result) => {
        res.send(result);
    })
});

app.get('/avis-verif', (req, res) => {
    const request = "SELECT * FROM avisverif"
    db.query(request, (error, result) => {
        res.send(result);
    })
});

app.delete('/employes/remove/:email', (req, res) => {
    const { email } = req.params
    const request = 'DELETE FROM employes WHERE email = ?'
    db.query(request, email, (error, result) => {
        if (error) {
            console.log(error)
        }
    })
});

app.delete('/services/remove/:name', (req, res) => {
    const { name } = req.params
    const request = 'DELETE FROM services WHERE name = ?';
    db.query(request, name, (error, result) => {
        if (error) {
            console.log(error);
        }
    })
});

app.delete('/voitures/remove/:id', (req, res) => {
    const { id } = req.params
    const request = "DELETE FROM voitures WHERE id = ?";
    db.query(request, id, (error, result) => {
        if (error) {
            console.log(error);
        }
    })
});

app.delete('/avis-non-verif/remove/:id', (req, res) => {
    const { id } = req.params
    const request = "DELETE FROM avisnonverif WHERE id = ?";
    db.query(request, id, (error, result) => {
        if (error) {
            console.log(error);
        }
    })
});

app.delete('/avis-verif/remove', (req, res) => {
    const request = "DELETE FROM avisverif";
    db.query(request, (error, result) => {
        if (error) {
            console.log(error);
        }
    })
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    console.log('email request', req.body.email);
    console.log('password request', req.body.password);
    console.log('Je me connecte');

    db.query("SELECT * FROM employes WHERE email = ?", [email], async (err, results) => {
        if (err) {
            console.log('dans le if error')
            res.status(500).send('Erreur dans la recherche du compte employé');
        }
        if (results.length === 0) { //On rentre ici si l'email est incorrect
            console.log('Utilisateur non trouvé');
            res.status(401).send('Utilisateur non trouvé');
        }

        const user = results[0];
        console.log('user' + user);
        console.log('password user', user.password);
        console.log('password ', password)

        if (user.password.includes("admin")) {
            try {
                console.log('je suis avant ismatched admin')
                const isMatched = user.password === password
                if (isMatched) {
                    const token = jwt.sign({ user_id: user.id, email: user.email }, process.env.JWT_SECRET, {
                        expiresIn: '24h'
                    })
                    console.log('ici est le token admin', token)
                    res.status(200).json({ success: true, message: 'Connexion réussie', role: "Admin", token })
                } else {
                    res.status(401).json({ success: false, message: 'Connexion échoué' })
                }
            } catch (err) {
                console.log(err)
                res.status(500).send('Erreur lors de la vérification du mot de passe')
            }
        } else {
            try {
                console.log('je suis avant ismatched')
                const isMatched = await bcrypt.compare(password, user.password)
                if (isMatched) {
                    const token = jwt.sign({ user_id: user.id, email: user.email }, process.env.JWT_SECRET, {
                        expiresIn: '24h'
                    })
                    console.log('ici est le token employé', token)
                    res.status(200).json({ success: true, message: 'Connexion réussie', role: "Employé", token })
                } else {
                    res.status(401).json({ success: false, message: 'Connexion échoué' })
                }
            } catch (err) {
                console.log(err)
                res.status(500).send('Erreur lors de la vérification du mot de passe')
            }
        }
        /*bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                console.log('je suis dans if result')
                res.status(200).json({ success: true, message: "connexion réussis" });
            } else {
                console.log('else bcrypt')
                res.status(401).json({ success: false, message: "mot de passe incorrect" });
            }
        })*/
    })
});

/*
function verifyToken(req, res, next) {
    const bearerHeader = req.headers['authorization'];
    console.log('bearerHeader', bearerHeader);
    if (typeof bearerHeader !== "undefined") {
        const bearer = bearerHeader.split(' ');
        console.log('bearer', bearer);
        const bearerToken = bearer[1];
        console.log('bearerToken', bearerToken);
        jwt.verify(bearerToken, process.env.JWT_SECRET, (err, authData) => {
            if (err) {
                res.status(403).send('Token érroné');
            } else {
                req.token = bearerToken;
                req.authData = authData;
                next();
            }
        })
    }
}*/

function verifyToken(req, res, next) {
    const bearerToken = req.headers['authorization'];
    console.log('bearerToken', bearerToken);
    if (typeof bearerToken !== "undefined") {
        jwt.verify(bearerToken, process.env.JWT_SECRET, (err, authData) => {
            console.log(authData)
            if (err) {
                res.status(403).send('Token érroné');
            } else {
                req.token = bearerToken;
                req.authData = authData;
                next();
            }
        })
    }
}


app.post('/addService', verifyToken, upload.single('uploadImage'), (req, res) => {
    const { name, content } = req.body;
    const imageName = req.file ? req.file.filename : null;
    console.log('req.token addservice', req.token)
    console.log('req.authdata addservice', req.authData)

    db.query("INSERT INTO services (name, content, image) VALUES (?, ?, ?)", [name, content, imageName], (error, result) => {
        if (error) {
            console.log(error);
            res.status(500).send('Erreur lors de l\'ajout du service');
        }
        else {
            res.status(201).send('Service ajouter avec succès');
        }
    })
});

app.post('/addVoiture', verifyToken, upload.single('uploadImage'), (req, res) => {
    const { brand, km, price, yearsCirculation } = req.body;
    const imageName = req.file ? req.file.filename : null;

    db.query("INSERT INTO voitures (brand, km, price, yearsCirculation, image) VALUES (?, ?, ?, ?, ?)", [brand, km, price, yearsCirculation, imageName], (error, result) => {
        if (error) {
            console.log(error);
            res.status(500).send('Erreur lors de l\'ajout de la voiture');
        }
        else {
            res.status(201).send('Voiture ajouté avec succès');
        }
    })
});

app.post('/add-avis-non-verif', (req, res) => {
    const { name, message, note } = req.body;

    db.query("INSERT INTO avisnonverif (name, message, note) VALUE (?, ?, ?)", [name, message, note], (error, result) => {
        if (error) {
            console.log(error);
            res.status(500).send('Erreur lors de l\'ajout de l\'avis');
        }
        else {
            res.status(201).send('Avis ajouté avec succès');
        }
    })
})

app.post('/add-avis-verif', verifyToken, (req, res) => {
    const { name, message, note } = req.body;

    db.query("INSERT INTO avisverif (name, message, note) VALUE (?, ?, ?)", [name, message, note], (error, result) => {
        if (error) {
            console.log(error);
            res.status(500).send('Erreur lors de l\'ajout de l\'avis');
        }
        else {
            res.status(201).send('Avis ajouté avec succès');
        }
    })
})

app.listen(port, () => {
    console.log('server en écoute au port ' + port);
});