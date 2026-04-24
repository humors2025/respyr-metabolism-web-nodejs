const multer = require('multer');

const storage = multer.memoryStorage(); // 🔐 no disk storage

const upload = multer({
  storage,
  limits: {
    fileSize: 2 * 1024 * 1024, // 2MB max
  },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('Only image files allowed'));
    }
    cb(null, true);
  },
});

module.exports = upload;
