// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const { body, validationResult } = require('express-validator');

// === CONFIG ===
const app = express();
app.use(express.json());

const allowedOrigins = [
    'http://127.0.0.1:5501',
    'http://localhost:5500',
    'https://your-frontend-domain.com'  // for production
];

// serve uploaded images
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// multer config
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage });


app.use(cors({
  origin: function (origin, callback) {
    // allow requests with no origin (like mobile apps, curl)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = "CORS policy: Not allowed by CORS for origin " + origin;
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true,
}));
const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGODB_URI || 'mongodb+srv://QuickRent:QuickRent123@cluster0.i0u9yrv.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

// === MONGOOSE MODEL ===
const userSchema = new mongoose.Schema({
    name: { type: String, trim: true, required: true, minlength: 2 },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    phone: { type: String },
    role: { type: String, enum: ['tenant', 'owner'], default: 'tenant' },
    type: { type: String, enum: ['tenant', 'owner', 'admin'], default: 'tenant' },
    company: { type: String, default: null },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const propertySchema = new mongoose.Schema({
    title: { type: String, required: true },
    type: { type: String, required: true },
    address: { type: String, required: true },
    city: { type: String },
    state: { type: String },
    pincode: { type: String },
    latitude: { type: Number },
    longitude: { type: Number },
    price: { type: Number, required: true },
    bedrooms: { type: Number, required: true },
    bathrooms: { type: Number, required: true },
    description: { type: String, required: true },
    amenities: [{ type: String }],
    images: [{ type: String }],
    roommateRequired: { type: Boolean, default: false },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
    age: { type: Number },
    floor: { type: Number },
    totalFloors: { type: Number },
    facing: { type: String },
}, { timestamps: true });


// ✅ REMOVE 2dsphere index – no GeoJSON
// propertySchema.index({ location: "2dsphere" });

const Property = mongoose.model("Property", propertySchema);

// === AUTH MIDDLEWARE ===
function auth(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ message: 'No token' });

    const [bearer, token] = authHeader.split(' ');
    if (bearer !== 'Bearer' || !token) return res.status(401).json({ message: 'Invalid token format' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // { userId, role }
        next();
    } catch (err) {
        return res.status(401).json({ message: 'Token not valid' });
    }
}

// === ROUTES ===

// Health check
app.get('/', (req, res) => res.json({ ok: true, message: 'QuickRent API running' }));

// SIGNUP
app.post('/api/auth/signup',
    [
        body('name').isLength({ min: 2 }),
        body('email').isEmail(),
        body('password').isLength({ min: 6 }),
        body('phone').optional().isMobilePhone('any'),
        body('role').optional().isIn(['tenant', 'owner'])
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { name, email, password, phone, role, company } = req.body;

        try {
            const existing = await User.findOne({ email: email.toLowerCase() });
            if (existing) return res.status(400).json({ message: 'Email already registered' });

            const hashed = await bcrypt.hash(password, 10);
            const user = new User({
                name,
                email: email.toLowerCase(),
                password: hashed,
                phone,
                role,
                company: role === 'owner' ? company || null : null
            });
            await user.save();

            const payload = { userId: user._id, role: user.role };
            const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

            res.status(201).json({
                message: 'User created',
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    phone: user.phone,
                    role: user.role,
                    company: user.company
                },
                token
            });

        } catch (err) {
            console.error('Signup error:', err);
            res.status(500).json({ message: 'Server error' });
        }
    });

// LOGIN
app.post('/api/auth/login',
    [
        body('email').isEmail(),
        body('password').exists()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { email, password } = req.body;
        try {
            const user = await User.findOne({ email: email.toLowerCase() });
            if (!user) return res.status(400).json({ message: 'Invalid credentials' });

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

            const payload = { userId: user._id, role: user.role };
            const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

            res.json({
                message: 'Login successful',
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    phone: user.phone,
                    role: user.role,
                    company: user.company
                },
                token
            });

        } catch (err) {
            console.error('Login error:', err);
            res.status(500).json({ message: 'Server error' });
        }
    });

// GET current user
app.get('/api/auth/me', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json({ user });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

async function adminAuth(req, res, next) {
    if (!req.user) return res.status(401).json({ message: "Unauthorized" });

    try {
        const user = await User.findById(req.user.userId);
        if (!user || user.type !== "admin") {
            return res.status(403).json({ message: "Forbidden: Admins only" });
        }
        next();
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
}


// GET /api/admin/users
app.get('/api/admin/users', auth, adminAuth, async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json({ users }); // make sure it's { users: [...] }
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// GET /api/admin/properties – list all properties for admin
app.get('/api/admin/properties', auth, adminAuth, async (req, res) => {
    try {
        const properties = await Property.find()
            .populate('owner', 'name email');

        // Shape data for admin table (adds ownerName and location fields expected by frontend)
        const shaped = properties.map((p) => ({
            _id: p._id,
            title: p.title,
            ownerName: p.owner && p.owner.name ? p.owner.name : null,
            location: p.city || p.state || p.address || '',
            price: p.price,
            status: p.status
        }));

        res.json({ properties: shaped });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// GET /api/properties – only approved properties
app.get('/api/properties', async (req, res) => {
    try {
        const properties = await Property.find({ status: 'approved' });
        res.json({ properties });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});


app.post('/api/properties', auth, upload.array('images', 10), async (req, res) => {
    try {
        const {
            title, type, address, city, state, pincode,
            latitude, longitude, price, bedrooms, bathrooms,
            description, amenities, age, floor, totalFloors, facing, roommateRequired
        } = req.body;

        if (!title || !type || !address || !price || !bedrooms || !bathrooms || !description) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        if (!req.files || req.files.length < 4) {
            return res.status(400).json({ error: 'At least 4 images required' });
        }

        const imageUrls = req.files.map((file) => `/uploads/${file.filename}`);

        const amenitiesArray = amenities ? JSON.parse(amenities) : [];

        const property = new Property({
            title,
            type,
            address,
            city,
            state,
            pincode,
            latitude: latitude ? parseFloat(latitude) : null,
            longitude: longitude ? parseFloat(longitude) : null,
            price: parseFloat(price),
            bedrooms: parseInt(bedrooms),
            bathrooms: parseInt(bathrooms),
            description,
            amenities: amenitiesArray,
            images: imageUrls,
            roommateRequired: [true, 'true', 'on', '1'].includes((roommateRequired ?? '').toString().toLowerCase()),
            owner: req.user.userId,
            age: age ? parseInt(age) : 0,
            floor: floor ? parseInt(floor) : 1,
            totalFloors: totalFloors ? parseInt(totalFloors) : 1,
            facing: facing || 'north'
        });

        await property.save();
        res.json({ message: 'Property created successfully', property });

    } catch (err) {
        console.error('Create property error:', err);
        res.status(500).json({ error: err.message });
    }
});


// PUT /api/admin/properties/:id/approve
app.put('/api/admin/properties/:id/approve', auth, adminAuth, async (req, res) => {
    try {
        const prop = await Property.findById(req.params.id);
        if (!prop) return res.status(404).json({ message: 'Property not found' });

        prop.status = 'approved';
        await prop.save();
        res.json({ message: 'Property approved' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// PUT /api/admin/properties/:id/reject
app.put('/api/admin/properties/:id/reject', auth, adminAuth, async (req, res) => {
    try {
        const prop = await Property.findById(req.params.id);
        if (!prop) return res.status(404).json({ message: 'Property not found' });

        prop.status = 'rejected';
        await prop.save();
        res.json({ message: 'Property rejected' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/properties/:id', async (req, res) => {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ message: 'Invalid property ID' });
    }

    try {
        const property = await Property.findById(id).populate('owner', 'name email phone');

        if (!property || property.status !== 'approved') {
            return res.status(404).json({ message: 'Property not found' });
        }

        res.json({ property });
    } catch (err) {
        console.error('Property fetch error:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

// === BOOKING MODEL ===
const bookingSchema = new mongoose.Schema({
    property: { type: mongoose.Schema.Types.ObjectId, ref: "Property", required: true },
    tenant: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    message: { type: String },
    status: { type: String, enum: ["pending", "confirmed", "rejected"], default: "pending" }
}, { timestamps: true });

const Booking = mongoose.model("Booking", bookingSchema);

// === BOOKINGS ROUTES ===

// Create booking
app.post("/api/bookings", auth, async (req, res) => {
    try {
        const { propertyId, startDate, endDate, message } = req.body;

        if (!mongoose.Types.ObjectId.isValid(propertyId)) {
            return res.status(400).json({ message: "Invalid property ID" });
        }

        const booking = new Booking({
            property: propertyId,
            tenant: req.user.userId,
            startDate,
            endDate,
            message
        });

        await booking.save();
        res.status(201).json({ message: "Booking created successfully", booking });
    } catch (err) {
        console.error("Booking error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// Get my bookings
app.get("/api/bookings/me", auth, async (req, res) => {
    try {
        const bookings = await Booking.find({ tenant: req.user.userId })
            .populate({
                path: "property",
                select: "title price owner",
                populate: { path: "owner", select: "name email" }
            })
            .populate("tenant", "name email");

        res.json({ bookings });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
});

// Owner notifications: get bookings for properties they own
app.get("/api/bookings/owner", auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user || user.role !== "owner") {
            return res.status(403).json({ message: "Only owners can view notifications" });
        }

        const bookings = await Booking.find()
            .populate({ path: "property", select: "title owner", populate: { path: "owner", select: "name email" } })
            .populate("tenant", "name email")
            .where("property")
            .in(await Property.find({ owner: req.user.userId }).distinct("_id"));

        res.json({ bookings });
    } catch (err) {
        console.error("Owner notifications error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// === MESSAGE MODEL ===
const messageSchema = new mongoose.Schema({
    booking: { type: mongoose.Schema.Types.ObjectId, ref: "Booking", required: true },
    sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    text: { type: String, required: true },
}, { timestamps: true });

const Message = mongoose.model("Message", messageSchema);

// === MESSAGES ROUTES ===

// Send a message
app.post("/api/messages", auth, async (req, res) => {
    try {
        const { bookingId, text } = req.body;

        if (!bookingId || !text) {
            return res.status(400).json({ message: "Booking ID and text are required" });
        }

        const booking = await Booking.findById(bookingId);
        if (!booking) return res.status(404).json({ message: "Booking not found" });

        // Ensure user is either tenant or property owner
        const property = await Property.findById(booking.property);
        if (!property) return res.status(404).json({ message: "Property not found" });

        if (
            booking.tenant.toString() !== req.user.userId &&
            property.owner.toString() !== req.user.userId
        ) {
            return res.status(403).json({ message: "Not authorized" });
        }

        const message = new Message({
            booking: bookingId,
            sender: req.user.userId,
            text,
        });

        await message.save();
        res.status(201).json({ message: "Message sent", data: message });
    } catch (err) {
        console.error("Message error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// Get chat messages for a booking
app.get("/api/messages/:bookingId", auth, async (req, res) => {
    try {
        const bookingId = req.params.bookingId;
        const booking = await Booking.findById(bookingId);
        if (!booking) return res.status(404).json({ message: "Booking not found" });

        const property = await Property.findById(booking.property);
        if (!property) return res.status(404).json({ message: "Property not found" });

        if (
            booking.tenant.toString() !== req.user.userId &&
            property.owner.toString() !== req.user.userId
        ) {
            return res.status(403).json({ message: "Not authorized" });
        }

        const messages = await Message.find({ booking: bookingId })
            .populate("sender", "name email")
            .sort({ createdAt: 1 });

        res.json({ messages });
    } catch (err) {
        console.error("Fetch messages error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// === OWNER BOOKING ACTIONS ===
app.put("/api/bookings/:id/approve", auth, async (req, res) => {
    try {
        const booking = await Booking.findById(req.params.id);
        if (!booking) return res.status(404).json({ message: "Booking not found" });

        // Ensure requester is the property's owner
        const property = await Property.findById(booking.property);
        if (!property) return res.status(404).json({ message: "Property not found" });
        if (property.owner.toString() !== req.user.userId) {
            return res.status(403).json({ message: "Only the property owner can approve" });
        }

        booking.status = "confirmed";
        await booking.save();
        res.json({ message: "Booking approved", booking });
    } catch (err) {
        console.error("Approve booking error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

app.put("/api/bookings/:id/reject", auth, async (req, res) => {
    try {
        const booking = await Booking.findById(req.params.id);
        if (!booking) return res.status(404).json({ message: "Booking not found" });

        const property = await Property.findById(booking.property);
        if (!property) return res.status(404).json({ message: "Property not found" });
        if (property.owner.toString() !== req.user.userId) {
            return res.status(403).json({ message: "Only the property owner can reject" });
        }

        booking.status = "rejected";
        await booking.save();
        res.json({ message: "Booking rejected", booking });
    } catch (err) {
        console.error("Reject booking error:", err);
        res.status(500).json({ message: "Server error" });
    }
});


// === START SERVER ===
mongoose.connect(MONGO_URI)
    .then(() => {
        console.log('MongoDB connected');
        app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
    })
    .catch(err => {
        console.error('MongoDB connection error:', err);
        process.exit(1);
    });



