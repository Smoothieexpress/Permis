// ============================================
// BACKEND COMPLET LUXESTAY COTONOU
// ============================================

// Importation des modules
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

// Initialisation de l'application Express
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'luxestay-secret-key-2024-cotonou';

// Middleware
app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:5500', 'http://localhost:5500'],
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================
// CONNEXION À MONGODB
// ============================================

// URI MongoDB (utilisez MongoDB Atlas ou local)
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/luxestay-cotonou';

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB connecté avec succès'))
.catch(err => console.error('❌ Erreur MongoDB:', err));

// ============================================
// MODÈLES MONGODB
// ============================================

// Modèle Utilisateur
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Le nom est requis'],
        trim: true
    },
    email: {
        type: String,
        required: [true, "L'email est requis"],
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^\S+@\S+\.\S+$/, 'Email invalide']
    },
    phone: {
        type: String,
        required: [true, 'Le téléphone est requis'],
        match: [/^[0-9+\-\s()]{8,20}$/, 'Numéro de téléphone invalide']
    },
    password: {
        type: String,
        required: [true, 'Le mot de passe est requis'],
        minlength: 6
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// Hacher le mot de passe avant sauvegarde
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Méthode pour comparer les mots de passe
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Méthode pour générer un token JWT
userSchema.methods.generateAuthToken = function() {
    return jwt.sign(
        { userId: this._id, email: this.email, role: this.role },
        JWT_SECRET,
        { expiresIn: '7d' }
    );
};

const User = mongoose.model('User', userSchema);

// Modèle Studio
const studioSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Le nom du studio est requis'],
        trim: true
    },
    description: {
        type: String,
        required: [true, 'La description est requise']
    },
    location: {
        quarter: {
            type: String,
            required: [true, 'Le quartier est requis']
        },
        address: String,
        city: {
            type: String,
            default: 'Cotonou'
        },
        coordinates: {
            lat: Number,
            lng: Number
        }
    },
    pricePerNight: {
        type: Number,
        required: [true, 'Le prix par nuit est requis'],
        min: 0
    },
    images: [{
        url: String,
        caption: String,
        isPrimary: {
            type: Boolean,
            default: false
        }
    }],
    features: [{
        name: String,
        icon: String,
        description: String
    }],
    amenities: [String],
    maxGuests: {
        type: Number,
        default: 2,
        min: 1
    },
    minimumStay: {
        type: Number,
        default: 2,
        min: 1
    },
    isAvailable: {
        type: Boolean,
        default: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

const Studio = mongoose.model('Studio', studioSchema);

// Modèle Réservation
const bookingSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    studio: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Studio',
        required: true
    },
    checkIn: {
        type: Date,
        required: [true, "La date d'arrivée est requise"]
    },
    checkOut: {
        type: Date,
        required: [true, "La date de départ est requise"]
    },
    nights: {
        type: Number,
        required: true,
        min: 1
    },
    guests: {
        adults: {
            type: Number,
            default: 1,
            min: 1
        },
        children: {
            type: Number,
            default: 0,
            min: 0
        }
    },
    totalPrice: {
        type: Number,
        required: true,
        min: 0
    },
    status: {
        type: String,
        enum: ['pending', 'confirmed', 'cancelled', 'completed'],
        default: 'pending'
    },
    specialRequests: String,
    paymentStatus: {
        type: String,
        enum: ['pending', 'paid', 'refunded'],
        default: 'pending'
    },
    paymentMethod: {
        type: String,
        enum: ['wave', 'mtn_mobile', 'orange_money', 'cash', 'card'],
        default: 'cash'
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// Calculer le nombre de nuits avant sauvegarde
bookingSchema.pre('save', function(next) {
    if (this.checkIn && this.checkOut) {
        const diffTime = Math.abs(this.checkOut - this.checkIn);
        this.nights = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    }
    next();
});

const Booking = mongoose.model('Booking', bookingSchema);

// ============================================
// MIDDLEWARE D'AUTHENTIFICATION
// ============================================

const authMiddleware = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({
                success: false,
                error: 'Accès refusé. Token manquant.'
            });
        }
        
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId).select('-password');
        
        if (!user) {
            return res.status(401).json({
                success: false,
                error: 'Utilisateur non trouvé.'
            });
        }
        
        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        console.error('Erreur authentification:', error.message);
        
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                error: 'Token invalide.'
            });
        }
        
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                error: 'Token expiré.'
            });
        }
        
        res.status(500).json({
            success: false,
            error: 'Erreur d\'authentification.'
        });
    }
};

const adminMiddleware = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({
            success: false,
            error: 'Accès réservé aux administrateurs.'
        });
    }
    next();
};

// ============================================
// ROUTES API
// ============================================

// Route de test
app.get('/api', (req, res) => {
    res.json({
        success: true,
        message: '🚀 API LuxeStay Cotonou en ligne !',
        version: '1.0.0',
        endpoints: {
            auth: {
                register: 'POST /api/auth/register',
                login: 'POST /api/auth/login',
                profile: 'GET /api/auth/profile'
            },
            studio: {
                getStudio: 'GET /api/studio',
                checkAvailability: 'POST /api/studio/availability'
            },
            bookings: {
                create: 'POST /api/bookings',
                myBookings: 'GET /api/bookings/my',
                cancel: 'PUT /api/bookings/:id/cancel'
            },
            users: {
                updateProfile: 'PUT /api/users/profile'
            }
        }
    });
});

// Route de santé
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        status: 'healthy',
        timestamp: new Date().toISOString(),
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// ============================================
// AUTHENTIFICATION
// ============================================

// Inscription
app.post('/api/auth/register', [
    body('name')
        .trim()
        .notEmpty().withMessage('Le nom est requis')
        .isLength({ min: 2 }).withMessage('Le nom doit faire au moins 2 caractères'),
    
    body('email')
        .trim()
        .notEmpty().withMessage("L'email est requis")
        .isEmail().withMessage('Email invalide')
        .normalizeEmail(),
    
    body('phone')
        .trim()
        .notEmpty().withMessage('Le téléphone est requis')
        .matches(/^[0-9+\-\s()]{8,20}$/).withMessage('Numéro de téléphone invalide'),
    
    body('password')
        .notEmpty().withMessage('Le mot de passe est requis')
        .isLength({ min: 6 }).withMessage('Le mot de passe doit faire au moins 6 caractères')
        .matches(/^(?=.*[A-Za-z])(?=.*\d)/).withMessage('Le mot de passe doit contenir au moins une lettre et un chiffre')
], async (req, res) => {
    try {
        // Validation
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array()
            });
        }
        
        const { name, email, phone, password } = req.body;
        
        // Vérifier si l'utilisateur existe déjà
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                error: 'Un compte existe déjà avec cet email.'
            });
        }
        
        // Vérifier si le téléphone existe déjà
        const existingPhone = await User.findOne({ phone });
        if (existingPhone) {
            return res.status(400).json({
                success: false,
                error: 'Un compte existe déjà avec ce numéro de téléphone.'
            });
        }
        
        // Créer l'utilisateur
        const user = new User({
            name,
            email,
            phone,
            password
        });
        
        await user.save();
        
        // Générer le token JWT
        const token = user.generateAuthToken();
        
        // Préparer la réponse
        const userResponse = {
            _id: user._id,
            name: user.name,
            email: user.email,
            phone: user.phone,
            role: user.role,
            isVerified: user.isVerified,
            createdAt: user.createdAt
        };
        
        res.status(201).json({
            success: true,
            message: '🎉 Inscription réussie ! Bienvenue chez LuxeStay.',
            user: userResponse,
            token
        });
        
    } catch (error) {
        console.error('Erreur inscription:', error);
        
        // Gestion des erreurs MongoDB
        if (error.code === 11000) {
            return res.status(400).json({
                success: false,
                error: 'Cet email ou numéro de téléphone est déjà utilisé.'
            });
        }
        
        res.status(500).json({
            success: false,
            error: 'Erreur serveur lors de l\'inscription.',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Connexion
app.post('/api/auth/login', [
    body('email')
        .trim()
        .notEmpty().withMessage("L'email est requis")
        .isEmail().withMessage('Email invalide')
        .normalizeEmail(),
    
    body('password')
        .notEmpty().withMessage('Le mot de passe est requis')
], async (req, res) => {
    try {
        // Validation
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array()
            });
        }
        
        const { email, password } = req.body;
        
        // Trouver l'utilisateur
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({
                success: false,
                error: 'Email ou mot de passe incorrect.'
            });
        }
        
        // Vérifier le mot de passe
        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                error: 'Email ou mot de passe incorrect.'
            });
        }
        
        // Générer le token JWT
        const token = user.generateAuthToken();
        
        // Préparer la réponse
        const userResponse = {
            _id: user._id,
            name: user.name,
            email: user.email,
            phone: user.phone,
            role: user.role,
            isVerified: user.isVerified,
            createdAt: user.createdAt
        };
        
        res.json({
            success: true,
            message: '✅ Connexion réussie !',
            user: userResponse,
            token
        });
        
    } catch (error) {
        console.error('Erreur connexion:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur serveur lors de la connexion.'
        });
    }
});

// Profil utilisateur
app.get('/api/auth/profile', authMiddleware, async (req, res) => {
    try {
        res.json({
            success: true,
            user: req.user
        });
    } catch (error) {
        console.error('Erreur profil:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur serveur lors de la récupération du profil.'
        });
    }
});

// ============================================
// STUDIO
// ============================================

// Obtenir les informations du studio
app.get('/api/studio', async (req, res) => {
    try {
        // Pour l'instant, on a un seul studio
        let studio = await Studio.findOne();
        
        // Si aucun studio n'existe, créer un exemple
        if (!studio) {
            studio = new Studio({
                name: 'Studio Executive - Les Cocotiers',
                description: 'Studio moderne de 45m² avec terrasse privée et vue panoramique. Équipement haut de gamme, climatisation intelligente et service conciergerie inclus.',
                location: {
                    quarter: 'Les Cocotiers',
                    address: 'Résidence Les Palmiers, Cotonou',
                    city: 'Cotonou',
                    coordinates: {
                        lat: 6.3546,
                        lng: 2.4212
                    }
                },
                pricePerNight: 25000,
                images: [
                    {
                        url: 'https://images.unsplash.com/photo-1560448204-e02f11c3d0e2',
                        caption: 'Vue principale du salon',
                        isPrimary: true
                    },
                    {
                        url: 'https://images.unsplash.com/photo-1586023492125-27b2c045efd7',
                        caption: 'Cuisine équipée'
                    },
                    {
                        url: 'https://images.unsplash.com/photo-1552321554-5fefe8c9ef14',
                        caption: 'Salle de bain spa'
                    }
                ],
                features: [
                    {
                        name: 'Climatisation Intelligente',
                        icon: '❄️',
                        description: 'Contrôle individuel par pièce'
                    },
                    {
                        name: 'Wi-Fi Haut Débit',
                        icon: '📶',
                        description: 'Fibre optique 100Mb/s'
                    },
                    {
                        name: 'TV 4K & Netflix',
                        icon: '📺',
                        description: 'Écran 55" avec abonnements'
                    },
                    {
                        name: 'Cuisine Professionnelle',
                        icon: '🍳',
                        description: 'Électroménagers Siemens'
                    },
                    {
                        name: 'Spa Privatif',
                        icon: '🛁',
                        description: 'Jacuzzi et hammam'
                    },
                    {
                        name: 'Sécurité 24/7',
                        icon: '🔐',
                        description: 'Gardiennage et caméras'
                    }
                ],
                amenities: ['Piscine', 'Parking privé', 'Ascenseur', 'Terrasse', 'Buanderie', 'Service ménage'],
                maxGuests: 2,
                minimumStay: 2,
                isAvailable: true
            });
            
            await studio.save();
        }
        
        res.json({
            success: true,
            studio
        });
        
    } catch (error) {
        console.error('Erreur récupération studio:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur serveur lors de la récupération du studio.'
        });
    }
});

// Vérifier la disponibilité
app.post('/api/studio/availability', async (req, res) => {
    try {
        const { checkIn, checkOut } = req.body;
        
        if (!checkIn || !checkOut) {
            return res.status(400).json({
                success: false,
                error: 'Les dates d\'arrivée et de départ sont requises.'
            });
        }
        
        const checkInDate = new Date(checkIn);
        const checkOutDate = new Date(checkOut);
        const today = new Date();
        
        // Validation des dates
        if (isNaN(checkInDate.getTime()) || isNaN(checkOutDate.getTime())) {
            return res.status(400).json({
                success: false,
                error: 'Dates invalides.'
            });
        }
        
        if (checkInDate < today) {
            return res.status(400).json({
                success: false,
                error: 'La date d\'arrivée ne peut pas être dans le passé.'
            });
        }
        
        if (checkOutDate <= checkInDate) {
            return res.status(400).json({
                success: false,
                error: 'La date de départ doit être après la date d\'arrivée.'
            });
        }
        
        // Vérifier les réservations existantes
        const overlappingBookings = await Booking.find({
            status: { $in: ['pending', 'confirmed'] },
            $or: [
                {
                    checkIn: { $lt: checkOutDate },
                    checkOut: { $gt: checkInDate }
                }
            ]
        });
        
        const isAvailable = overlappingBookings.length === 0;
        const nights = Math.ceil((checkOutDate - checkInDate) / (1000 * 60 * 60 * 24));
        
        // Obtenir le prix du studio
        const studio = await Studio.findOne();
        const totalPrice = studio ? nights * studio.pricePerNight : 0;
        
        res.json({
            success: true,
            available: isAvailable,
            dates: {
                checkIn: checkInDate.toISOString().split('T')[0],
                checkOut: checkOutDate.toISOString().split('T')[0],
                nights
            },
            price: {
                perNight: studio?.pricePerNight || 25000,
                total: totalPrice,
                currency: 'FCFA'
            },
            message: isAvailable 
                ? 'Le studio est disponible pour ces dates.' 
                : 'Le studio n\'est pas disponible pour ces dates.'
        });
        
    } catch (error) {
        console.error('Erreur vérification disponibilité:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur serveur lors de la vérification de la disponibilité.'
        });
    }
});

// ============================================
// RÉSERVATIONS
// ============================================

// Créer une réservation
app.post('/api/bookings', authMiddleware, [
    body('checkIn')
        .notEmpty().withMessage("La date d'arrivée est requise")
        .isISO8601().withMessage('Format de date invalide'),
    
    body('checkOut')
        .notEmpty().withMessage("La date de départ est requise")
        .isISO8601().withMessage('Format de date invalide'),
    
    body('guests.adults')
        .isInt({ min: 1 }).withMessage('Au moins 1 adulte est requis')
], async (req, res) => {
    try {
        // Validation
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array()
            });
        }
        
        const { checkIn, checkOut, guests, specialRequests, paymentMethod } = req.body;
        
        // Convertir les dates
        const checkInDate = new Date(checkIn);
        const checkOutDate = new Date(checkOut);
        
        // Vérifier les dates
        if (checkOutDate <= checkInDate) {
            return res.status(400).json({
                success: false,
                error: 'La date de départ doit être après la date d\'arrivée.'
            });
        }
        
        // Vérifier la disponibilité
        const overlappingBookings = await Booking.find({
            status: { $in: ['pending', 'confirmed'] },
            $or: [
                {
                    checkIn: { $lt: checkOutDate },
                    checkOut: { $gt: checkInDate }
                }
            ]
        });
        
        if (overlappingBookings.length > 0) {
            return res.status(400).json({
                success: false,
                error: 'Le studio n\'est pas disponible pour ces dates.'
            });
        }
        
        // Obtenir le studio
        const studio = await Studio.findOne();
        if (!studio) {
            return res.status(404).json({
                success: false,
                error: 'Studio non trouvé.'
            });
        }
        
        // Calculer le prix
        const nights = Math.ceil((checkOutDate - checkInDate) / (1000 * 60 * 60 * 24));
        const totalPrice = nights * studio.pricePerNight;
        
        // Vérifier le séjour minimum
        if (nights < studio.minimumStay) {
            return res.status(400).json({
                success: false,
                error: `Le séjour minimum est de ${studio.minimumStay} nuit(s).`
            });
        }
        
        // Vérifier le nombre maximum d'invités
        const totalGuests = (guests.adults || 1) + (guests.children || 0);
        if (totalGuests > studio.maxGuests) {
            return res.status(400).json({
                success: false,
                error: `Le studio ne peut accueillir que ${studio.maxGuests} personne(s) maximum.`
            });
        }
        
        // Créer la réservation
        const booking = new Booking({
            user: req.user._id,
            studio: studio._id,
            checkIn: checkInDate,
            checkOut: checkOutDate,
            nights,
            guests: {
                adults: guests.adults || 1,
                children: guests.children || 0
            },
            totalPrice,
            specialRequests: specialRequests || '',
            paymentMethod: paymentMethod || 'cash',
            status: 'pending'
        });
        
        await booking.save();
        
        // Populate pour la réponse
        await booking.populate('studio', 'name location images pricePerNight');
        
        res.status(201).json({
            success: true,
            message: '🎉 Réservation créée avec succès !',
            booking: {
                _id: booking._id,
                checkIn: booking.checkIn,
                checkOut: booking.checkOut,
                nights: booking.nights,
                guests: booking.guests,
                totalPrice: booking.totalPrice,
                status: booking.status,
                specialRequests: booking.specialRequests,
                paymentMethod: booking.paymentMethod,
                paymentStatus: booking.paymentStatus,
                createdAt: booking.createdAt,
                studio: booking.studio
            },
            nextSteps: [
                'Notre équipe va vous contacter dans les 24h pour confirmer votre réservation.',
                'Préparez votre pièce d\'identité pour l\'enregistrement.',
                'Le paiement se fera sur place à votre arrivée.'
            ]
        });
        
    } catch (error) {
        console.error('Erreur création réservation:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur serveur lors de la création de la réservation.'
        });
    }
});

// Obtenir les réservations de l'utilisateur
app.get('/api/bookings/my', authMiddleware, async (req, res) => {
    try {
        const bookings = await Booking.find({ user: req.user._id })
            .populate('studio', 'name location images pricePerNight')
            .sort({ createdAt: -1 });
        
        res.json({
            success: true,
            count: bookings.length,
            bookings: bookings.map(booking => ({
                _id: booking._id,
                checkIn: booking.checkIn,
                checkOut: booking.checkOut,
                nights: booking.nights,
                guests: booking.guests,
                totalPrice: booking.totalPrice,
                status: booking.status,
                paymentMethod: booking.paymentMethod,
                paymentStatus: booking.paymentStatus,
                specialRequests: booking.specialRequests,
                createdAt: booking.createdAt,
                studio: booking.studio
            }))
        });
        
    } catch (error) {
        console.error('Erreur récupération réservations:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur serveur lors de la récupération des réservations.'
        });
    }
});

// Annuler une réservation
app.put('/api/bookings/:id/cancel', authMiddleware, async (req, res) => {
    try {
        const bookingId = req.params.id;
        
        const booking = await Booking.findOne({
            _id: bookingId,
            user: req.user._id
        });
        
        if (!booking) {
            return res.status(404).json({
                success: false,
                error: 'Réservation non trouvée.'
            });
        }
        
        // Vérifier si l'annulation est possible
        const now = new Date();
        const hoursBeforeCheckIn = (booking.checkIn - now) / (1000 * 60 * 60);
        
        if (hoursBeforeCheckIn < 24) {
            return res.status(400).json({
                success: false,
                error: 'L\'annulation doit être faite au moins 24h avant l\'arrivée.'
            });
        }
        
        if (booking.status === 'cancelled') {
            return res.status(400).json({
                success: false,
                error: 'Cette réservation est déjà annulée.'
            });
        }
        
        if (booking.status === 'completed') {
            return res.status(400).json({
                success: false,
                error: 'Impossible d\'annuler une réservation déjà terminée.'
            });
        }
        
        // Annuler la réservation
        booking.status = 'cancelled';
        booking.updatedAt = new Date();
        await booking.save();
        
        res.json({
            success: true,
            message: '✅ Réservation annulée avec succès.',
            booking: {
                _id: booking._id,
                status: booking.status,
                updatedAt: booking.updatedAt
            }
        });
        
    } catch (error) {
        console.error('Erreur annulation réservation:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur serveur lors de l\'annulation de la réservation.'
        });
    }
});

// ============================================
// UTILISATEURS
// ============================================

// Mettre à jour le profil
app.put('/api/users/profile', authMiddleware, [
    body('name')
        .optional()
        .trim()
        .isLength({ min: 2 }).withMessage('Le nom doit faire au moins 2 caractères'),
    
    body('phone')
        .optional()
        .trim()
        .matches(/^[0-9+\-\s()]{8,20}$/).withMessage('Numéro de téléphone invalide'),
    
    body('currentPassword')
        .optional()
        .notEmpty().withMessage('Le mot de passe actuel est requis pour changer le mot de passe'),
    
    body('newPassword')
        .optional()
        .isLength({ min: 6 }).withMessage('Le nouveau mot de passe doit faire au moins 6 caractères')
        .matches(/^(?=.*[A-Za-z])(?=.*\d)/).withMessage('Le mot de passe doit contenir au moins une lettre et un chiffre')
], async (req, res) => {
    try {
        // Validation
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array()
            });
        }
        
        const { name, phone, currentPassword, newPassword } = req.body;
        const user = await User.findById(req.user._id);
        
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'Utilisateur non trouvé.'
            });
        }
        
        // Mettre à jour les informations de base
        if (name) user.name = name;
        if (phone) user.phone = phone;
        
        // Changer le mot de passe si demandé
        if (newPassword) {
            if (!currentPassword) {
                return res.status(400).json({
                    success: false,
                    error: 'Le mot de passe actuel est requis pour changer le mot de passe.'
                });
            }
            
            const isPasswordValid = await user.comparePassword(currentPassword);
            if (!isPasswordValid) {
                return res.status(401).json({
                    success: false,
                    error: 'Mot de passe actuel incorrect.'
                });
            }
            
            user.password = newPassword;
        }
        
        user.updatedAt = new Date();
        await user.save();
        
        // Générer un nouveau token si le mot de passe a changé
        let newToken;
        if (newPassword) {
            newToken = user.generateAuthToken();
        }
        
        // Préparer la réponse
        const userResponse = {
            _id: user._id,
            name: user.name,
            email: user.email,
            phone: user.phone,
            role: user.role,
            isVerified: user.isVerified,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt
        };
        
        const response = {
            success: true,
            message: '✅ Profil mis à jour avec succès.',
            user: userResponse
        };
        
        if (newToken) {
            response.token = newToken;
            response.message = '✅ Profil et mot de passe mis à jour avec succès.';
        }
        
        res.json(response);
        
    } catch (error) {
        console.error('Erreur mise à jour profil:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur serveur lors de la mise à jour du profil.'
        });
    }
});

// ============================================
// ROUTES ADMIN (optionnel pour plus tard)
// ============================================

// Obtenir toutes les réservations (admin)
app.get('/api/admin/bookings', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const bookings = await Booking.find()
            .populate('user', 'name email phone')
            .populate('studio', 'name location')
            .sort({ createdAt: -1 });
        
        res.json({
            success: true,
            count: bookings.length,
            bookings
        });
        
    } catch (error) {
        console.error('Erreur récupération réservations admin:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur serveur.'
        });
    }
});

// Mettre à jour le statut d'une réservation (admin)
app.put('/api/admin/bookings/:id/status', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { status } = req.body;
        const validStatuses = ['pending', 'confirmed', 'cancelled', 'completed'];
        
        if (!validStatuses.includes(status)) {
            return res.status(400).json({
                success: false,
                error: `Statut invalide. Valeurs autorisées: ${validStatuses.join(', ')}`
            });
        }
        
        const booking = await Booking.findById(req.params.id);
        if (!booking) {
            return res.status(404).json({
                success: false,
                error: 'Réservation non trouvée.'
            });
        }
        
        booking.status = status;
        booking.updatedAt = new Date();
        await booking.save();
        
        res.json({
            success: true,
            message: `Statut de la réservation mis à jour: ${status}`,
            booking
        });
        
    } catch (error) {
        console.error('Erreur mise à jour statut:', error);
        res.status(500).json({
            success: false,
            error: 'Erreur serveur.'
        });
    }
});

// ============================================
// GESTION DES ERREURS
// ============================================

// Route 404
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        error: 'Route non trouvée.'
    });
});

// Gestionnaire d'erreurs global
app.use((err, req, res, next) => {
    console.error('Erreur non gérée:', err);
    
    const statusCode = err.statusCode || 500;
    const message = err.message || 'Erreur serveur interne';
    
    res.status(statusCode).json({
        success: false,
        error: message,
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
});

// ============================================
// DÉMARRAGE DU SERVEUR
// ============================================

app.listen(PORT, () => {
    console.log(`🚀 Serveur backend démarré sur le port ${PORT}`);
    console.log(`📡 API disponible à: http://localhost:${PORT}/api`);
    console.log(`🏥 Endpoint santé: http://localhost:${PORT}/api/health`);
    console.log(`🔗 Frontend: Placez vos fichiers HTML dans le dossier frontend/`);
});