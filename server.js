const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
const mysql = require("mysql");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

const SECRET_KEY = process.env.SECRET_KEY;

// Connexion à la base de données
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
};

let db;

function handleDisconnect() {
  db = mysql.createConnection(dbConfig);

  db.connect((err) => {
    if (err) {
      console.error("Erreur de connexion à MySQL : ", err);
      setTimeout(handleDisconnect, 2000); // Réessaye après 2 secondes
    } else {
      console.log("Connecté à MySQL !");
    }
  });

  db.on("error", (err) => {
    console.error("Erreur MySQL :", err);
    if (err.code === "PROTOCOL_CONNECTION_LOST" || err.code === "ECONNRESET") {
      console.log("Reconnexion en cours...");
      handleDisconnect();
    } else {
      throw err;
    }
  });
}

handleDisconnect();

const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];

  if (token) {
    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};


// Route de connexion
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  // Vérifier si l'utilisateur existe
  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    if (result.length === 0) return res.status(401).json({ error: "Email ou mot de passe incorrect" });

    const user = result[0];

    // Vérifier le mot de passe
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: "Email ou mot de passe incorrect" });

    // Générer un token JWT
    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });

    res.json({ token, user: { id: user.id, email: user.email, typeUser: user.typeUser } });
  });
});


// Route d'inscription
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  // Vérifier si l'utilisateur existe déjà
  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
    if (results.length > 0) {
      return res.status(400).json({ message: "L'utilisateur existe déjà" });
    }

    // Hacher le mot de passe
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Insérer l'utilisateur dans la base de données
    db.query(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword],
      (err, result) => {
        if (err) {
          return res.status(500).json({ message: "Erreur serveur" });
        }
        res.status(201).json({ message: "Utilisateur enregistré avec succès" });
      }
    );
  });
});

//----------------------------------------------------------------------- Register

// Vérifier si un numéro d'inventaire existe déjà
app.get("/devices/check-numero-inventaire", (req, res) => {
  const { numero_inventaire } = req.query;
  const query = "SELECT COUNT(*) AS count FROM devices WHERE numero_inventaire = ?";
  db.query(query, [numero_inventaire], (err, results) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    res.json({ exists: results[0].count > 0 });
  });
});


// Calculer prochaine date

const calculateNextPreventifDate = (createdAt, periodePreventif) => {
  const date = new Date(createdAt);
  switch (periodePreventif) {
    case 'JOURNALIERE':
      date.setDate(date.getDate() + 1);
      break;
    case 'HEBDOMADAIRE':
      date.setDate(date.getDate() + 7);
      break;
    case 'QUINZOMADAIRE':
       date.setDate(date.getDate() + 15);
       break;
    case 'MENSUELLE':
      date.setMonth(date.getMonth() + 1);
      break;
    case 'BI MENSUELLE':
      date.setMonth(date.getMonth() + 2);
      break;
    case 'TRIMESTRIELLE':
      date.setMonth(date.getMonth() + 3);
      break;
    case 'SEMESTRIELLE':
      date.setMonth(date.getMonth() + 6);
      break;
    case 'ANNUELLE':
      date.setFullYear(date.getFullYear() + 1);
      break;
    case 'BIENNAL':
      date.setFullYear(date.getFullYear() + 2);
      break;
    case 'TRIENNAL':
      date.setFullYear(date.getFullYear() + 3);
      break;
    case 'QUADRIENNAL':
      date.setFullYear(date.getFullYear() + 4);
      break;
    case 'QUINQUENNAL':
      date.setFullYear(date.getFullYear() + 5);
      break;
    default:
      return null;
  }
  return date.toISOString().split('T')[0]; // Return date in YYYY-MM-DD format
};

app.use('/devices', authenticateJWT);

// Ajouter un équipement
app.post("/devices", (req, res) => {
  const { numero_inventaire, device_name, localisation, frequence, dateInstallation, description, date_prochain_preventif } = req.body;
  const dateProchainGraissage = calculateNextPreventifDate(dateInstallation, frequence);
  const etat_id = 1;

  db.query("SELECT COUNT(*) AS count FROM devices WHERE numero_inventaire = ?", [numero_inventaire], (err, results) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    if (results[0].count > 0) return res.status(400).json({ error: "Numéro d'inventaire déjà utilisé" });

    const query = "INSERT INTO devices (numero_inventaire, device_name, localisation, frequence, dateInstallation, description, date_prochain_preventif, etat_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    db.query(query, [numero_inventaire, device_name, localisation, frequence, dateInstallation, description, dateProchainGraissage, etat_id], (err, result) => {
      if (err) return res.status(500).json({ error: "Erreur serveur" });
      res.status(201).json({ message: "Équipement ajouté avec succès" });
    });
  });
});

app.use('/localisations', authenticateJWT);
// Récupérer les localisations
app.get("/localisations", (req, res) => {
  db.query("SELECT id, nom_localisation FROM localisation", (err, results) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    res.json(results);
  });
});

// Récupérer les fréquences de maintenance
app.get("/frequences", (req, res) => {
  db.query("SELECT * FROM frequence", (err, results) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    res.json(results);
  });
});

// Récupérer les etats de l'equipement
app.get("/etatDevices", (req, res) => {
  db.query("SELECT id, etat FROM etatDevices", (err, results) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    res.json(results);
  });
});

// Récupérer tous les équipements
app.get("/devices", (req, res) => {
  const query = `
    SELECT * FROM devices
  `;

  db.query(query, (err, results) => {
    if (err) return res.status(500).send(err);
    res.status(200).send(results);
  });
});




// Compter le nombre d'équipements

app.get('/devicesCount', (req, res) => {
  const query = 'SELECT COUNT(*) AS count FROM devices';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Erreur lors de la récupération du nombre d equipements', err);
      return res.status(500).send('Erreur lors de la récupération du nombre d equipements');
    }
    res.json(results);
  });
});

app.get("/temps-indisponibilite", (req, res) => {
  const queryDevices = `SELECT numero_inventaire, dateInstallation FROM devices`;

  db.query(queryDevices, (err, devices) => {
    if (err) return res.status(500).send("Erreur lors de la récupération des appareils");

    const results = [];
    let processed = 0;

    if (devices.length === 0) return res.send([]);

    devices.forEach((device) => {
      const numero = device.numero_inventaire;
      const dateInstallation = new Date(device.dateInstallation);
      const now = new Date();
      const heuresDepuisInstallation = (now - dateInstallation) / 3600000;

      const preventifQuery = `
        SELECT SUM(TIMESTAMPDIFF(SECOND, date_debut_intervention, date_fin_intervention)) AS total_seconds
        FROM operationprevntif
        WHERE numero_inventaire = ? AND date_debut_intervention IS NOT NULL AND date_fin_intervention IS NOT NULL
      `;

      const correctifQuery = `
        SELECT SUM(TIMESTAMPDIFF(SECOND, date_debut_intervention, date_fin_intervention)) AS total_seconds
        FROM operationcorrective
        WHERE numero_inventaire = ? AND date_debut_intervention IS NOT NULL AND date_fin_intervention IS NOT NULL
      `;

      db.query(preventifQuery, [numero], (err1, preventifRows) => {
        if (err1) return res.status(500).send("Erreur lors du calcul préventif");

        db.query(correctifQuery, [numero], (err2, correctifRows) => {
          if (err2) return res.status(500).send("Erreur lors du calcul correctif");

          const preventifSec = preventifRows[0].total_seconds || 0;
          const correctifSec = correctifRows[0].total_seconds || 0;
          const indispoHeures = (preventifSec + correctifSec) / 3600;

          let taux = 100;
          if (heuresDepuisInstallation > 0) {
            taux = ((heuresDepuisInstallation - indispoHeures) / heuresDepuisInstallation) * 100;
          }

          results.push({
            numero_inventaire: numero,
            taux_disponibilite: Math.max(0, taux.toFixed(2)),
          });

          processed++;
          if (processed === devices.length) {
            res.send(results);
          }
        });
      });
    });
  });
});




//--------------------------------------------------------- Anomalies

app.use('/anomlies', authenticateJWT);

app.post('/anomlies', (req, res) => {
  const { anomlie, numero_inventaire, operateur } = req.body;
  const createdAt = new Date();
  const query = 'INSERT INTO anomlies (anomlie, numero_inventaire, created_at, operateur) VALUES (?, ?, ?, ?)';
  db.query(query, [anomlie, numero_inventaire, createdAt, operateur], (err, result) => {
    if (err) {
      res.status(500).send(err);
      console.log("Erreur SQL :", err); // Log de l'erreur SQL
    } else {
      res.status(201).send(result);
    }
  });
});

app.get('/anomlies', (req, res) => {
  const query = 'SELECT * FROM anomlies';
  db.query(query, (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.status(200).send(results);
    }
  });
});

app.get('/anomliesavecdesignation', (req, res) => {
  const query = 'SELECT anomlies.id, anomlies.anomlie, anomlies.numero_inventaire, anomlies.created_at, anomlies.operateur, devices.device_name, devices.equipement_localisation FROM anomlies JOIN devices ON anomlies.numero_inventaire = devices.numero_inventaire ORDER BY anomlies.created_at DESC';
  db.query(query, (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.status(200).send(results);
    }
  });
});

app.put('/anomlies/:id', (req, res) => {
  const { id } = req.params;
  const { anomlie, numero_inventaire, operateur } = req.body;
  const query = 'UPDATE anomlies SET anomlie = ?, numero_inventaire = ?, operateur = ? WHERE id = ?';
  db.query(query, [anomlie, numero_inventaire, operateur, id], (err, result) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.status(200).send(result);
    }
  });
});

app.delete('/anomlies/:id', (req, res) => {
  const { id } = req.params;
  const query = 'DELETE FROM anomlies WHERE id = ?';
  db.query(query, [id], (err, result) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.status(200).send(result);
    }
  });
});


app.post('/photos_anomalies', async (req, res) => {
  const { numero_inventaire, operateur, photos = [], anomlie, destinataire } = req.body; // photos est un tableau vide par défaut

  if (!numero_inventaire || !operateur || !anomlie || !destinataire) {
    return res.status(400).json({ message: 'Les champs numero_inventaire, operateur, destinataire et photos (tableau) sont requis' });
  }

  const date = new Date();

  const queryPhoto = `
    INSERT INTO photos_anomalies (numero_inventaire, date, operateur, photo)
    VALUES (?, ?, ?, ?)
  `;

  try {
    // Insertion de chaque photo dans la table
    for (let photoData of photos) {
      await new Promise((resolve, reject) => {
        db.query(queryPhoto, [numero_inventaire, date, operateur, photoData], (err, result) => {
          if (err) {
            return reject(err);
          }
          resolve(result);
        });
      });
    }

    // Préparer les photos en tant que pièces jointes pour l'email en utilisant les données reçues
    const attachments = photos.map((photo, index) => ({
      filename: `photo_${index + 1}.jpg`,
      content: photo.split('base64,')[1],
      encoding: 'base64'
    }));

    // Envoyer l'email avec les photos en pièces jointes
    sendEmail(
       destinataire,
      'Anomalie détectée',
      `Une nouvelle anomalie a été détectée avec les détails suivants :
      \nNuméro inventaire: ${numero_inventaire}
      \nOpérateur: ${operateur}
      \nAnomalie: ${anomlie}`, // Inclure l'anomalie ici
      attachments
    );

    // Confirmation de succès
    res.status(201).json({ message: 'Photos anomalies ajoutées avec succès' });

  } catch (error) {
    console.error('Erreur lors de l\'ajout des photos d\'anomalie:', error);
    res.status(500).json({ message: 'Erreur interne du serveur' });
  }
});




//--------------------------------------------------------- Anomalies

//--------------------------------------------------------- Correctif

app.get('/operationCorrectiveCount', (req, res) => {
    const sql = "SELECT id, etat, date_debut_intervention, date_fin_intervention, date_signalement FROM operationcorrective";
    db.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(results);
    });
});
// Récupérer toutes les opérations correctives
app.get("/operationCorrective", (req, res) => {
  const query = `SELECT operationcorrective.id, operationcorrective.numero_inventaire, devices.device_name, operationcorrective.description_panne, operationcorrective.date_signalement, operationcorrective.date_debut_intervention, operationcorrective.date_fin_intervention, operationcorrective.description_diagnostic, operationcorrective.etat FROM operationcorrective JOIN devices ON operationcorrective.numero_inventaire = devices.numero_inventaire ORDER BY operationcorrective.date_signalement DESC`;

  db.query(query, (err, results) => {
    if (err) return res.status(500).send(err);
    res.status(200).send(results);
  });
});

app.get("/operationCorrective/:id", (req, res) => {
  const { id } = req.params;

  const query = `SELECT operationcorrective.id, operationcorrective.numero_inventaire, devices.device_name, operationcorrective.description_panne, operationcorrective.date_signalement, operationcorrective.date_debut_intervention, operationcorrective.date_fin_intervention, operationcorrective.description_diagnostic, operationcorrective.diagnostic_par, operationcorrective.repare_par, operationcorrective.etat
                 FROM operationcorrective
                 JOIN devices ON operationcorrective.numero_inventaire = devices.numero_inventaire
                 WHERE operationcorrective.id = ?`; //  Ajout de la condition WHERE

  db.query(query, [id], (err, results) => {
    if (err) return res.status(500).send(err);

    if (results.length === 0) {
      return res.status(404).json({ message: "Opération corrective non trouvée" });
    }

    res.status(200).json(results[0]); // ✅ Retourne un seul objet au lieu d'un tableau
  });
});


// Ajouter une nouvelle opération corrective avec vérification
app.post("/operationCorrective", (req, res) => {
  const { numero_inventaire, description_panne, signale_par, etat } = req.body;
  const date_signalement = new Date().toISOString().slice(0, 19).replace("T", " "); // Format YYYY-MM-DD HH:MM:SS

  if (!numero_inventaire || !description_panne) {
    return res.status(400).send("Le numéro d'inventaire et la description de la panne sont obligatoires.");
  }

  // Vérifier si une opération corrective est en cours pour cet équipement
  const checkQuery = `
    SELECT id FROM operationCorrective
    WHERE numero_inventaire = ?
    AND date_fin_intervention IS NULL
  `;

  db.query(checkQuery, [numero_inventaire], (err, result) => {
    if (err) {
      console.error("Erreur SQL (Vérification intervention en cours) :", err);
      return res.status(500).send("Erreur lors de la vérification.");
    }

    if (result.length > 0) {
      return res.status(400).json({ error: "Une intervention est déjà en cours sur cet équipement." });
    }

    // Insérer la nouvelle opération corrective
    const insertQuery = `
      INSERT INTO operationCorrective (numero_inventaire, description_panne, date_signalement, signale_par, etat)
      VALUES (?, ?, ?, ?, ?)
    `;

    db.query(insertQuery, [numero_inventaire, description_panne, date_signalement, signale_par, etat], (err, result) => {
      if (err) {
        console.error("Erreur SQL (INSERT) :", err);
        return res.status(500).send("Erreur lors de l'insertion dans la base de données.");
      }

      // Mettre à jour l'état de l'appareil dans devices
      const updateQuery = `UPDATE devices SET etat_id = ? WHERE numero_inventaire = ?`;

      db.query(updateQuery, [etat, numero_inventaire], (updateErr) => {
        if (updateErr) {
          console.error("Erreur SQL (UPDATE) :", updateErr);
          return res.status(500).send("Erreur lors de la mise à jour de l'état de l'appareil.");
        }

        res.status(201).send({ message: "Opération corrective ajoutée et état mis à jour avec succès", id: result.insertId });
      });
    });
  });
});



// Mettre à jour une opération corrective pour ajouter ou modifier le diagnostic
app.put("/operationCorrectiveDiagnostic/:id", (req, res) => {
  const { id } = req.params;
  const { description_diagnostic, diagnostic_par } = req.body;

  const query = `
    UPDATE operationCorrective
    SET description_diagnostic = ?, diagnostic_par = ?
    WHERE id = ?
  `;

  db.query(query, [description_diagnostic, diagnostic_par, id], (err) => {
    if (err) {
      console.error("Erreur SQL:", err); // 🔍 Voir les erreurs SQL
      return res.status(500).send(err);
    }
    res.status(200).send({ message: "Opération corrective mise à jour avec succès" });
  });
});


app.put("/operationCorrectiveReparation/:id", (req, res) => {
  const { id } = req.params;
  const { description_reparation, repare_par } = req.body;
  const date_fin_intervention = new Date().toISOString().slice(0, 19).replace("T", " "); // Format YYYY-MM-DD HH:MM:SS
  const etat = 1;

  console.log("Requête reçue:", req.body, req.params);

  const updateReparationQuery = `
    UPDATE operationCorrective
    SET date_fin_intervention = ?,
        description_reparation = ?, repare_par = ?, etat = ?
    WHERE id = ?
  `;

  db.query(
    updateReparationQuery,
    [date_fin_intervention, description_reparation, repare_par, etat, id],
    (err) => {
      if (err) {
        console.error("Erreur SQL:", err);
        return res.status(500).send(err);
      }

      // Récupération du numero_inventaire lié à cette réparation
      const getNumeroInventaireQuery = `SELECT numero_inventaire FROM operationCorrective WHERE id = ?`;

      db.query(getNumeroInventaireQuery, [id], (err, result) => {
        if (err) {
          console.error("Erreur SQL lors de la récupération du numero_inventaire:", err);
          return res.status(500).send(err);
        }

        if (result.length === 0 || !result[0].numero_inventaire) {
          console.warn("Aucun numero_inventaire trouvé pour cette réparation.");
          return res.status(200).send({ message: "Réparation mise à jour, mais aucun numero_inventaire trouvé." });
        }

        const numeroInventaire = result[0].numero_inventaire;

        // Trouver l'ID du device correspondant dans la table devices
        const getDeviceIdQuery = `SELECT id FROM devices WHERE numero_inventaire = ?`;

        db.query(getDeviceIdQuery, [numeroInventaire], (err, result) => {
          if (err) {
            console.error("Erreur SQL lors de la récupération de l'ID du device:", err);
            return res.status(500).send(err);
          }

          if (result.length === 0) {
            console.warn("Aucun appareil trouvé pour ce numero_inventaire.");
            return res.status(200).send({ message: "Réparation mise à jour, mais aucun appareil trouvé." });
          }

          const deviceId = result[0].id;

          // Mise à jour de l'état du device
          const updateDeviceQuery = `UPDATE devices SET etat_id = 1 WHERE id = ?`;

          db.query(updateDeviceQuery, [deviceId], (err) => {
            if (err) {
              console.error("Erreur SQL lors de la mise à jour de l'état du device:", err);
              return res.status(500).send(err);
            }
            res.status(200).send({ message: "Réparation et état du device mis à jour avec succès" });
          });
        });
      });
    }
  );
});


app.put("/commencerIntervention/:id", (req, res) => {
  const { id } = req.params;
  const date_debut_intervention = new Date().toISOString().slice(0, 19).replace("T", " "); // Format YYYY-MM-DD HH:MM:SS
  const etat = 3; // En maintenance

  // Vérifier si l'intervention est déjà commencée mais pas terminée
  const checkQuery = `
    SELECT date_debut_intervention, date_fin_intervention
    FROM operationCorrective
    WHERE id = ?
  `;

  db.query(checkQuery, [id], (err, result) => {
    if (err) {
      console.error("Erreur SQL lors de la vérification de l'intervention :", err);
      return res.status(500).json({ error: "Erreur lors de la vérification." });
    }

    if (result.length === 0) {
      return res.status(404).json({ error: "Intervention non trouvée." });
    }

    const { date_debut_intervention: debut, date_fin_intervention: fin } = result[0];

    if (debut && !fin) {
      return res.status(400).json({ error: "Cette intervention est déjà en cours." });
    }

    // Mise à jour de operationCorrective
    const updateCorrectiveQuery = `
      UPDATE operationCorrective
      SET date_debut_intervention = ?, etat = ?
      WHERE id = ?
    `;

    db.query(updateCorrectiveQuery, [date_debut_intervention, etat, id], (err, result) => {
      if (err) {
        console.error("Erreur SQL lors de la mise à jour de l'intervention :", err);
        return res.status(500).send(err);
      }

      // Récupération du numero_inventaire pour mettre à jour devices
      const getNumeroInventaireQuery = `SELECT numero_inventaire FROM operationCorrective WHERE id = ?`;

      db.query(getNumeroInventaireQuery, [id], (err, result) => {
        if (err) {
          console.error("Erreur SQL lors de la récupération du numero_inventaire :", err);
          return res.status(500).send(err);
        }

        if (result.length === 0 || !result[0].numero_inventaire) {
          return res.status(200).send({ message: "Intervention commencée, mais aucun numéro d'inventaire trouvé." });
        }

        const numeroInventaire = result[0].numero_inventaire;

        // Mise à jour de l'état dans devices
        const updateDeviceQuery = `UPDATE devices SET etat_id = ? WHERE numero_inventaire = ?`;

        db.query(updateDeviceQuery, [etat, numeroInventaire], (err) => {
          if (err) {
            console.error("Erreur SQL lors de la mise à jour de l'état de l'équipement :", err);
            return res.status(500).send(err);
          }

          res.status(200).send({ message: "Intervention commencée et état mis à jour avec succès." });
        });
      });
    });
  });
});






// Supprimer une opération corrective
app.delete("/operationCorrective/:id", (req, res) => {
  const { id } = req.params;

  const query = `DELETE FROM operationCorrective WHERE id = ?`;

  db.query(query, [id], (err) => {
    if (err) return res.status(500).send(err);
    res.status(200).send({ message: "Opération corrective supprimée avec succès" });
  });
});


//-------------------------------------------------------------------Correctif


//-------------------------------------------------------------------Preventif

// Récupérer toutes les opérations préventives
app.get("/planningPreventif", (req, res) => {
  const query = `
    SELECT id, numero_inventaire, description_preventif,
           date_debut_intervention, date_fin_intervention, operateur, etat
    FROM operationPrevntif
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Erreur SQL operationPreventifEnCours :", err);
      return res.status(500).json({ error: "Erreur lors de la récupération." });
    }
    res.status(200).json(results);
  });
});

// Récupérer toutes les opérations préventives
app.get("/planningPreventifAvecDesignation", (req, res) => {
  const query = `
    SELECT operationPrevntif.id, operationPrevntif.numero_inventaire,
           devices.device_name, operationPrevntif.description_preventif,
           operationPrevntif.date_debut_intervention, operationPrevntif.date_fin_intervention,
           operationPrevntif.operateur, operationPrevntif.etat
    FROM operationPrevntif
    JOIN devices ON operationPrevntif.numero_inventaire = devices.numero_inventaire ORDER BY operationPrevntif.id DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Erreur SQL operationPreventifEnCours :", err);
      return res.status(500).json({ error: "Erreur lors de la récupération." });
    }
    res.status(200).json(results);
  });
});

app.post("/commencerInterventionPreventif", (req, res) => {
  const { numero_inventaire, operateur } = req.body;
  const date_debut_intervention = new Date().toISOString().slice(0, 19).replace("T", " "); // Format YYYY-MM-DD HH:MM:SS
  const etat = 3; // En maintenance

  if (!numero_inventaire || !operateur) {
    return res.status(400).json({ error: "Le numéro d'inventaire et l'opérateur sont obligatoires" });
  }

  // Vérifier si une intervention préventive est déjà en cours
  const checkQuery = `
    SELECT id FROM operationPrevntif
    WHERE numero_inventaire = ?
    AND date_debut_intervention IS NOT NULL
    AND date_fin_intervention IS NULL
  `;

  db.query(checkQuery, [numero_inventaire], (err, result) => {
    if (err) {
      console.error("Erreur SQL lors de la vérification de l'intervention :", err);
      return res.status(500).json({ error: "Erreur lors de la vérification." });
    }

    if (result.length > 0) {
      return res.status(400).json({ error: "Intervention déjà commencée pour cet équipement." });
    }

    // Vérifier si l'équipement est en service (etat_id = 1)
    const checkEtatQuery = `SELECT etat_id FROM devices WHERE numero_inventaire = ?`;

    db.query(checkEtatQuery, [numero_inventaire], (err, result) => {
      if (err) {
        console.error("Erreur SQL lors de la vérification de l'état de l'équipement :", err);
        return res.status(500).json({ error: "Erreur lors de la vérification de l'état." });
      }

      if (result.length === 0 || result[0].etat_id !== 1) {
        return res.status(400).json({ error: "L'équipement n'est pas en service." });
      }

      // Insertion de la nouvelle opération préventive
      const insertQuery = `
        INSERT INTO operationPrevntif (numero_inventaire, date_debut_intervention, operateur, etat)
        VALUES (?, ?, ?, ?)
      `;

      db.query(insertQuery, [numero_inventaire, date_debut_intervention, operateur, etat], (err, result) => {
        if (err) {
          console.error("Erreur SQL lors de l'ajout de l'intervention préventive :", err);
          return res.status(500).json({ error: "Erreur lors de l'ajout de l'intervention préventive." });
        }

        // Mettre à jour l'état de l'équipement à "En maintenance"
        const updateDeviceQuery = `UPDATE devices SET etat_id = ? WHERE numero_inventaire = ?`;

        db.query(updateDeviceQuery, [etat, numero_inventaire], (updateErr) => {
          if (updateErr) {
            console.error("Erreur SQL lors de la mise à jour de l'état de l'équipement :", updateErr);
            return res.status(500).json({ error: "Erreur lors de la mise à jour de l'état de l'équipement." });
          }

          res.status(201).json({ message: "Intervention préventive commencée avec succès.", id: result.insertId });
        });
      });
    });
  });
});



app.put("/operationPreventif/:id", (req, res) => {
  const { id } = req.params;
  const { description_preventif, operateur } = req.body;
  const date_fin_intervention = new Date().toISOString().slice(0, 19).replace("T", " "); // Format YYYY-MM-DD HH:MM:SS
  const etat = 1; // Remettre l'équipement en service

  console.log("Requête reçue:", req.body, req.params);

  // Mise à jour de l'opération préventive
  const updatePreventifQuery = `
    UPDATE operationPrevntif
    SET date_fin_intervention = ?, description_preventif = ?, operateur = ?, etat = ?
    WHERE id = ?
  `;

  db.query(updatePreventifQuery, [date_fin_intervention, description_preventif, operateur, etat, id], (err) => {
    if (err) {
      console.error("Erreur SQL lors de la mise à jour de l'opération préventive:", err);
      return res.status(500).send(err);
    }

    // Récupérer le numero_inventaire et la fréquence de l'appareil
    const getDeviceQuery = `
      SELECT d.numero_inventaire, d.frequence
      FROM devices d
      JOIN operationPrevntif op ON d.numero_inventaire = op.numero_inventaire
      WHERE op.id = ?
    `;

    db.query(getDeviceQuery, [id], (err, result) => {
      if (err) {
        console.error("Erreur SQL lors de la récupération des informations du device :", err);
        return res.status(500).send(err);
      }

      if (result.length === 0 || !result[0].numero_inventaire) {
        console.warn("Aucun numéro d'inventaire trouvé pour cette opération.");
        return res.status(200).send({ message: "Opération mise à jour, mais aucun appareil trouvé." });
      }

      const { numero_inventaire, frequence } = result[0];

      // **Calcul de la nouvelle date préventive en ajoutant la fréquence à aujourd'hui**
      const nextPreventifDate = calculateNextPreventifDate(date_fin_intervention, frequence);
      if (!nextPreventifDate) {
        console.warn("Impossible de calculer la prochaine date de maintenance pour l'équipement :", numero_inventaire);
        return res.status(400).send({ error: "Fréquence de maintenance non reconnue." });
      }

      console.log(`🛠 Mise à jour du prochain préventif : ${nextPreventifDate} pour ${numero_inventaire}`);

      // Mise à jour de `devices` : état en service + nouvelle date de préventif
      const updateDeviceQuery = `
        UPDATE devices
        SET etat_id = ?, date_prochain_preventif = ?
        WHERE numero_inventaire = ?
      `;

      db.query(updateDeviceQuery, [etat, nextPreventifDate, numero_inventaire], (err) => {
        if (err) {
          console.error("Erreur SQL lors de la mise à jour de l'état du device :", err);
          return res.status(500).send(err);
        }
        res.status(200).send({ message: "Opération préventive et état du device mis à jour avec succès" });
      });
    });
  });
});


app.get("/operationPreventif/:id", (req, res) => {
  const { id } = req.params;

  const query = `
    SELECT id, numero_inventaire, description_preventif, date_debut_intervention, date_fin_intervention, operateur, etat
    FROM operationPrevntif
    WHERE id = ?
  `;

  db.query(query, [id], (err, results) => {
    if (err) {
      console.error("Erreur SQL lors de la récupération de l'opération préventive :", err);
      return res.status(500).json({ error: "Erreur lors de la récupération des données." });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "Aucune opération préventive trouvée avec cet ID." });
    }

    res.status(200).json(results[0]);
  });
});

app.get("/planningPreventifCount", (req, res) => {
  const today = new Date().toISOString().split("T")[0];

  const query = `
    SELECT COUNT(*) AS count FROM devices
    WHERE date_prochain_preventif IS NOT NULL AND date_prochain_preventif <= ?
  `;

  db.query(query, [today], (err, result) => {
    if (err) {
      console.error("Erreur SQL planningPreventifCount :", err);
      return res.status(500).json({ error: "Erreur lors de la récupération." });
    }
    res.json({ count: result[0].count });
    console.log(result[0].count);
  });
});

app.get("/operationPreventifEnCours", (req, res) => {
  const query = `
    SELECT COUNT(*) AS count FROM operationPrevntif
    WHERE date_debut_intervention IS NOT NULL
    AND date_fin_intervention IS NULL
  `;

  db.query(query, (err, result) => {
    if (err) {
      console.error("Erreur SQL operationPreventifEnCours :", err);
      return res.status(500).json({ error: "Erreur lors de la récupération." });
    }
    res.json({ count: result[0].count });
  });
});








//-------------------------------------------------------------------Preventif

app.get("/mtbf", (req, res) => {
  const sql = `
   SELECT
       DATE_FORMAT(date_fin_intervention, '%Y-%m') AS mois,
       AVG(diff_hours) AS mtbf_hours
   FROM (
       SELECT
           numero_inventaire,
           date_fin_intervention,
           TIMESTAMPDIFF(HOUR,
               LAG(date_fin_intervention) OVER (PARTITION BY numero_inventaire ORDER BY date_fin_intervention),
               date_fin_intervention
           ) AS diff_hours
       FROM operationCorrective
       WHERE date_fin_intervention IS NOT NULL
   ) AS subquery
   WHERE diff_hours IS NOT NULL
   GROUP BY mois
   ORDER BY mois;
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("❌ Erreur SQL MTBF :", err);
      return res.status(500).json({ error: err.message });
    }
    console.log("✅ Résultats MTBF :", results);
    res.json(results);
  });
});

app.get("/mttr", (req, res) => {
  const sql = `
    SELECT
      DATE_FORMAT(date_debut_intervention, '%Y-%m') AS mois,
      AVG(TIMESTAMPDIFF(HOUR, date_debut_intervention, date_fin_intervention)) AS mttr_hours
    FROM operationCorrective
    WHERE date_debut_intervention IS NOT NULL AND date_fin_intervention IS NOT NULL
    GROUP BY mois
    ORDER BY mois;
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("❌ Erreur SQL MTTR :", err);
      return res.status(500).json({ error: err.message });
    }
    console.log("✅ Résultats MTTR :", results);
    res.json(results);
  });
});





// Lancer le serveur
app.listen(5000, () => console.log("Serveur démarré sur http://localhost:5000"));
