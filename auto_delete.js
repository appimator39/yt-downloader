const fs = require('fs');
const path = require('path');

const folderPath = path.join(__dirname, "temp");

if (!fs.existsSync(folderPath)) {
    fs.mkdirSync(folderPath);
}

function deleteOldFiles() {
  fs.readdir(folderPath, (err, files) => {
    if (err) {
      console.error('Error reading directory:', err);
      return;
    }

    const currentTime = Date.now();

    files.forEach(file => {
      const filePath = path.join(folderPath, file);
      fs.stat(filePath, (err, stats) => {
        if (err) {
          console.error('Error getting file stats:', err);
          return;
        }

        const fileAge = currentTime - stats.mtime.getTime();
        const minutes = fileAge / (1000 * 60);

        if (minutes > 120) {
          fs.unlink(filePath, err => {
            if (err) {
              console.error('Error deleting file:', err);
              return;
            }
            console.log('Deleted:', filePath);
          });
        }
      });
    });
  });
}

// Call the function initially
deleteOldFiles();

// Set up interval to run the function every 5 minute
setInterval(deleteOldFiles, 5 * (60 * 1000));