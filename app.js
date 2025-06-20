const express = require("express");
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const bodyParser = require('body-parser');
const http = require("http");
const cors = require("cors");
const path = require("path");
const requestIp = require('request-ip');
const geoip = require('geoip-lite');
const fs = require('fs');
const { execSync } = require('child_process');
const os = require('os');
require("dotenv").config();
const jwt = require("jsonwebtoken");
const ytSearch = require('yt-search');
const socketIO = require('socket.io');
const { DateTime } = require('luxon');
const { v4: uuidv4 } = require('uuid');
const app = express();
const axios = require('axios');
const cheerio = require('cheerio');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { PassThrough } = require('stream');
const YTDlpWrap = require('yt-dlp-wrap').default;
const { Sequelize, DataTypes, Op } = require('sequelize');
const moment = require('moment')
const PORT = process.env.PORT;
const tempPath = path.join(__dirname, "temp");

if (!fs.existsSync(tempPath)) {
    fs.mkdirSync(tempPath);
} else {
    const files = fs.readdirSync(tempPath);
    files.forEach((file) => {
        const filePath = path.join(tempPath, file);

        // Agar file hai to usse delete karain
        if (fs.statSync(filePath).isFile()) {
            fs.unlinkSync(filePath);
            console.log(`${file} deleted successfully.`);
        }
    });
}


const logsFilePath = path.join(__dirname, 'logs.json');

const readLogs = () => {
    if (!fs.existsSync(logsFilePath)) {
        fs.writeFileSync(logsFilePath, JSON.stringify([]));
    }
    return JSON.parse(fs.readFileSync(logsFilePath));
};

const writeLogs = (logs) => {
    fs.writeFileSync(logsFilePath, JSON.stringify(logs, null, 2));
};

function getYtDlpPath() {
    try {
        const platform = os.platform();
        const command = platform === 'win32' ? 'where yt-dlp' : 'which yt-dlp';
        const path = execSync(command, { encoding: 'utf-8' }).trim();
        return path;
    } catch (error) {
        console.error("Error finding yt-dlp:", error.message);
        return null;
    }
}
const ytDlpPath = getYtDlpPath();

function getFFmpegPath() {
    try {
        const platform = os.platform();
        const command = platform === 'win32' ? 'where ffmpeg' : 'which ffmpeg';
        const path = execSync(command, { encoding: 'utf-8' }).trim();
        return path;
    } catch (error) {
        console.error("Error finding ffmpeg:", error.message);
        return null;
    }
}
const ffmpegPath = getFFmpegPath();


const sequelize = new Sequelize({
    dialect: "sqlite",
    storage: path.join(__dirname, "database.sqlite"),
    logging: false
});


const Admin = sequelize.define("Admin", {
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false,
    },
});

const Iframe = sequelize.define("Iframe", {
    slug: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    ad_code: {
        type: DataTypes.TEXT,
        allowNull: true,
    },
});


const Proxy = sequelize.define("Proxy", {
    address: {
        type: DataTypes.TEXT,
        allowNull: false,
        unique: true,
    },
    status: {
        type: DataTypes.TEXT,
        allowNull: true,
    }
});


sequelize.authenticate()
    .then(() => console.log('Database Connected'))
    .catch(err => console.log('Error: ', err))


async function syncDatabaseAndInsertRecords() {
    try {
        await sequelize.sync({ force: false });
        console.log("Database synchronized.");

        const adminCount = await Admin.count();
        if (adminCount < 1) {
            await Admin.create({
                email: "admin@mail.com",
                password: "1234",
            });
            console.log("Default admin record created.");
        } else {
            console.log("Admin already exists.");
        }

        const iframeCount = await Iframe.count();
        if (iframeCount < 1) {
            await Iframe.create({
                slug: "/",
                ad_code: "",
            });
            console.log("Default Iframe record created.");
        } else {
            console.log("Iframe already exists.");
        }
    } catch (error) {
        console.error("Error syncing database or inserting records:", error);
    }
}

syncDatabaseAndInsertRecords();




let youTubeUrlsForTesting = [
    "https://www.youtube.com/watch?v=MvsAesQ-4zA",
    "https://www.youtube.com/watch?v=tbnLqRW9Ef0",
    "https://www.youtube.com/watch?v=kvO_nHnvPtQ",
    "https://www.youtube.com/watch?v=tPEE9ZwTmy0",
    "https://www.youtube.com/watch?v=Wch3gJG2GJ4",
    "https://www.youtube.com/watch?v=TK4N5W22Gts",
    "https://www.youtube.com/watch?v=7-qGKqveZaM",
    "https://www.youtube.com/watch?v=TnNNG48DWHU",
    "https://www.youtube.com/watch?v=1O0yazhqaxs",
    "https://www.youtube.com/watch?v=5DEdR5lqnDE",
    "https://www.youtube.com/watch?v=GKv0qyeiBVg"
];

let currentIndex = 0;

function getNextYouTubeUrl() {
    const url = youTubeUrlsForTesting[currentIndex];
    currentIndex = (currentIndex + 1) % youTubeUrlsForTesting.length;
    return url;
}



let workingProxies = [];
let currentProxyIndex = -1;

function resetProxyCache() {
    workingProxies = [];
    currentIndex = -1;
}

async function getNextWorkingProxy() {
    try {
        if (workingProxies.length === 0) {
            workingProxies = await Proxy.findAll({
                where: { status: 'working' },
                order: [['updatedAt', 'DESC']]
            });

            if (workingProxies.length === 0) {
                throw new Error('No working proxies available');
            }
        }
        currentProxyIndex = (currentProxyIndex + 1) % workingProxies.length;
        return workingProxies[currentProxyIndex].address;
    } catch (error) {
        console.error('Error fetching working proxy:', error);
        return null;
    }
}










function checkProxies(proxy) {
    return new Promise((resolve, reject) => {
        let proxyUrl = `http://${proxy}`;
        const ytDlpWrap = new YTDlpWrap(ytDlpPath);
        let videoUrl = "https://www.youtube.com/watch?v=MvsAesQ-4zA";
        let DateObj = new Date();
        const outputPath = path.resolve(tempPath, `%(title)s_${DateObj.getSeconds()}.mp3`);
        let downloadedFileName = "";
        ytDlpWrap.exec([
            '--proxy', proxyUrl,
            videoUrl,
            '-o', outputPath,
            '--ffmpeg-location', ffmpegPath,
            '--no-part'
        ]).on('ytDlpEvent', (eventType, eventData) => {
            if (eventType === 'download') {
                if (eventData) {
                    const match = eventData.match(/Destination: (.+\.mp3)/);
                    if (match && match[1]) {
                        const fullPath = match[1];
                        const tempIndex = fullPath.indexOf('temp\\') !== -1 ? fullPath.indexOf('temp\\') + 5 : -1;
                        const fileName = tempIndex !== -1 ? fullPath.substring(tempIndex) : fullPath;
                        downloadedFileName = fileName;
                    }
                }
            }
        })
            .on('error', async (error) => {
                const errorMessage = error?.message || error.toString();
                if (errorMessage.includes('403') || errorMessage.includes('429') || errorMessage.includes("not a bot")) {
                    console.log(`Proxy blocked: ${proxy}`);
                    await Proxy.update(
                        { status: 'blocked' },
                        { where: { address: proxy } }
                    );
                    resetProxyCache();
                    reject(`Proxy blocked: ${proxy}`);
                } else {
                    console.log(error);
                    await Proxy.update(
                        { status: 'errored' },
                        { where: { address: proxy } }
                    );
                    resetProxyCache();
                    reject(`Error during Proxy checking`);
                }

            })
            .on('close', () => {
                deleteFileAfter50Minutes(path.join(tempPath, downloadedFileName))
                deleteFileAfter50Minutes(path.join(tempPath, downloadedFileName + ".webm"))
                resolve(downloadedFileName);
            });
    });
}


async function startProxyChecker() {
    while (true) {
        await sequelize.sync({ force: false });
        try {
            // Look for proxies with status 'unchecked' only
            const proxy = await Proxy.findOne({ where: { status: 'unchecked' } });
            if (proxy) {
                console.log(`Checking proxy: ${proxy.address}`);
                try {
                    // Check if the proxy is working
                    const fileName = await checkProxies(proxy.address);
                    console.log(`Proxy working: ${proxy.address}, Downloaded file: ${fileName}`);

                    // Update proxy status to 'working' after a successful check
                    await Proxy.update(
                        { status: 'working' },
                        { where: { id: proxy.id } }
                    );
                    resetProxyCache();
                } catch (error) {
                    console.log(error);
                }
            } else {
                // If no unchecked proxies, wait for 30 seconds before retrying
                await new Promise(resolve => setTimeout(resolve, 30000));
            }
        } catch (error) {
            // If an error occurs in the process, wait for 30 seconds before retrying
            await new Promise(resolve => setTimeout(resolve, 30000));
        }
    }
}

startProxyChecker();


async function startBlockProxyChecker() {
    while (true) {
        await sequelize.sync({ force: false });
        try {
            // Look for proxies with status 'unchecked' only
            const oneHourAgo = moment().subtract(1, 'hours').toDate();
            const proxy = await Proxy.findOne({ where: { status: 'blocked', updatedAt: { [Op.lte]: oneHourAgo } } });
            if (proxy) {
                console.log(`Checking proxy: ${proxy.address}`);
                try {
                    // Check if the proxy is working
                    const fileName = await checkProxies(proxy.address);
                    console.log(`Proxy working: ${proxy.address}, Downloaded file: ${fileName}`);

                    // Update proxy status to 'working' after a successful check
                    await Proxy.update(
                        { status: 'working' },
                        { where: { id: proxy.id } }
                    );
                    resetProxyCache();
                } catch (error) {
                    console.log(error);
                }
            } else {
                // If no unchecked proxies, wait for 30 seconds before retrying
                await new Promise(resolve => setTimeout(resolve, 30000));
            }
        } catch (error) {
            // If an error occurs in the process, wait for 30 seconds before retrying
            await new Promise(resolve => setTimeout(resolve, 30000));
        }
    }
}

startBlockProxyChecker();

async function startErroredProxyChecker() {
    while (true) {
        await sequelize.sync({ force: false });
        try {
            const proxy = await Proxy.findOne({ where: { status: 'errored' } });
            if (proxy) {
                console.log(`Checking proxy: ${proxy.address}`);
                try {
                    // Check if the proxy is working
                    const fileName = await checkProxies(proxy.address);
                    console.log(`Proxy working: ${proxy.address}, Downloaded file: ${fileName}`);

                    // Update proxy status to 'working' after a successful check
                    await Proxy.update(
                        { status: 'working' },
                        { where: { id: proxy.id } }
                    );
                    resetProxyCache();
                } catch (error) {
                    console.log(error);
                }
            } else {
                // If no unchecked proxies, wait for 30 seconds before retrying
                await new Promise(resolve => setTimeout(resolve, 30000));
            }
        } catch (error) {
            // If an error occurs in the process, wait for 30 seconds before retrying
            await new Promise(resolve => setTimeout(resolve, 30000));
        }
    }
}

startErroredProxyChecker();


function encodeToken(data) {
    try {
        const payload = data;
        return jwt.sign(payload, process.env.SECRET_KEY, { expiresIn: "1h" }); // Token expires in 1 hour
    } catch (error) {
        console.error("Encoding Error:", error);
        return null;
    }
}

function decodeToken(token) {
    try {
        return jwt.verify(token, process.env.SECRET_KEY);

    } catch (error) {
        return false;
    }
}


function deleteFileAfter50Minutes(fileName) {
    const delay = 50 * 60 * 1000;
    // File path ko ensure karna ke sahi ho
    const filePath = fileName;

    // SetTimeout ke zariye 50 minutes baad file delete karna
    setTimeout(() => {
        fs.unlink(filePath, (err) => {
            if (err) {

            } else {
                console.log(`File ${fileName} successfully delete kar diya gaya!`);
            }
        });
    }, delay);
}



async function fetchVideoTitle(link) {
    let videoId = extractYouTubeId(link);
    try {
        const results = await ytSearch(videoId);
        const filteredResult = results.videos
            .slice(0, 200)
            .filter(video => video.videoId === videoId)
            .map(video => ({
                title: video.title,
                videoId: video.videoId,
                thumbnail: video.thumbnail,
                duration: video.timestamp,
            }));

        return filteredResult;
    } catch (error) {
        console.error("Error fetching video title:", error);
        throw error;
    }
}




async function getVideoTitle(link, proxy) {
    const ytDlp = new YTDlpWrap();
    try {
        const output = await ytDlp.execPromise([
            link,
            "--get-title",
            "--proxy", proxy
        ]);

        return {
            status: true,
            title: output.trim()
        };
    } catch (error) {
        return {
            status: false,
            error: error.message
        };
    }
}









app.use(requestIp.mw());
app.use(cors({ origin: "*", credentials: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(cookieParser());
const csrfProtection = csrf({ cookie: true });
app.use(session({
    secret: 'mneudcfasriohopfcvwjrwefbrjguafjrwwgwrmbfdghgw',
    resave: false,
    saveUninitialized: false,
    store: new FileStore({
        path: path.join(__dirname, 'sessions'),
        ttl: 24 * 60 * 60,
        retries: 0
    }),
    cookie: {
        maxAge: 24 * 60 * 60 * 1000,
    }
}));

const refererDomains = [];

app.use((req, res, next) => {
    const referer = req.get('Referer');
    if (referer) {
        try {
            const refererDomain = new URL(referer).hostname;
            const timestamp = Date.now();

            // Check if the domain already exists
            const existingDomain = refererDomains.find(entry => entry.domain === refererDomain);
            if (!existingDomain) {
                refererDomains.push({ domain: refererDomain, timestamp });
            }

            // Remove old entries older than 24 hours
            const cutoff = Date.now() - 24 * 60 * 60 * 1000;
            while (refererDomains.length > 0 && refererDomains[0].timestamp < cutoff) {
                refererDomains.shift();
            }
        } catch (error) {
            console.error("Invalid referer URL:", error);
        }
    }
    next();
});



app.use((req, res, next) => {
    const clientIp = req.clientIp;
    const geo = geoip.lookup(clientIp);
    const country = geo ? geo.country : 'Unknown';
    req.clientCountry = country;
    next();
});




function isYouTubeURL(url) {
    const regex = /^(https?:\/\/)?(www\.|m\.)?(youtube\.com\/(watch\?v=[\w-]+|shorts\/[\w-]+|embed\/[\w-]+)|youtu\.be\/[\w-]+)([&?].*)?$/;
    return regex.test(url);
}

function extractYouTubeId(url) {
    const regex = /(?:https?:\/\/(?:www\.|m\.)?(?:youtube\.com\/(?:watch\?v=|embed\/|shorts\/)|youtu\.be\/))([\w-]+)/;
    const match = url.match(regex);
    return match ? match[1] : null;
}


app.use(async (req, res, next) => {
    if (req.method !== "GET") {
        return next();
    }
    try {
        const iframeRecord = await Iframe.findOne({ where: { slug: req.path } });
        if (iframeRecord) {
            const url = req.query.url;
            if (!url) {
                return res.status(400).send("<h1>URL is required</h1>");
            }
            if (!isYouTubeURL(url)) {
                return res.status(400).send("<h1>Not a valid YouTube url</h1>");
            }
            let data = {
                url,
                thumbnail: `https://img.youtube.com/vi/${extractYouTubeId(url)}/mqdefault.jpg`,
                ad_code: iframeRecord.ad_code,
                // token: encodeToken({ url, proxy,audio_file:`${uuidv4()}.mp3`,video_file:`${uuidv4()}.mp4`}),
            }
            res.render("iframe", data)
        }
    } catch (error) {
        console.error("Error checking slug in Iframe table:", error);
    }
    next();
});



function removeHttp(url) {
    return url.replace(/^http:\/\//, '');
}





const server = http.createServer(app);
const io = socketIO(server, {
    cors: {
        origin: "*",
        methods: ["GET"],
        credentials: true,
    },
});



io.on('connection', (socket) => {
    io.emit("console", { message: `<span style="color:#fff;"><span style="color:#16C47F;">User connected:</span> ${socket.id}</span>` });
    // Function to send referer domains
    const sendReferers = () => {
        refererDomains.forEach((entry) => {
            socket.emit("console", { message: `<span style="color:#FF9D23;">${entry.domain}</span>` });
        });
    };

    const interval = setInterval(sendReferers, 300000);

    socket.on('disconnect', () => {
        io.emit("console", { message: `<span style="color:#fff;"><span style="color:yellow;">User disconnected:</span> ${socket.id}</span>` });
        clearInterval(interval);
    });



    socket.on('addProxies', async ({ proxies }) => {
        if (!proxies || !Array.isArray(proxies) || proxies.length === 0) {
            socket.emit('proxiesAdded', { success: false, message: 'Proxies cannot be empty.' });
            return;
        }

        try {
            // Delete existing proxies
            await Proxy.destroy({ where: { address: proxies } });

            // Add new proxies to the database
            const newProxies = proxies.map((address) => ({ address, status: 'unchecked' }));
            await Proxy.bulkCreate(newProxies, { ignoreDuplicates: true });

            // Emit success to the client
            socket.emit('proxiesAdded', { success: true });

        } catch (error) {
            console.error('Error adding proxies:', error);
            socket.emit('proxiesAdded', { success: false, message: 'Failed to add proxies.' });
        }
    });



    socket.on("fetchingData", async (data) => {
        const videoUrl = data.url;
        const proxyUrl = `http://${await getNextWorkingProxy()}`;
        let domain = process.env.DOMAIN;
        let titleData = await fetchVideoTitle(videoUrl);
        let title = titleData.length > 0 
            ? titleData[0].title 
            : (await getVideoTitle(videoUrl, proxyUrl)).title;
        io.emit("console", { message: `<span style="color:#CB9DF0;">Fetching Data ${videoUrl}</span>` });
        io.emit("console", { message: `<span style="color:#CB9DF0;">Fetched Successfully ${videoUrl} ===> ${title}</span>` })
        socket.emit("data", { 
             title, 
            mp4_url: `${domain}/dl/${jwt.sign(
                { url: videoUrl, proxyUrl, format: "mp4", filename: `${getValidFileName(title)}.mp4` }, 
                process.env.SECRET_KEY, 
                { expiresIn: "1h" }
            )}`,
            mp3_url: `${domain}/dl/${jwt.sign(
                { url: videoUrl, proxyUrl, format: "mp3", filename: `${getValidFileName(title)}.mp3` }, 
                process.env.SECRET_KEY, 
                { expiresIn: "1h" }
            )}`
        });
            
    })


});









app.get('/api/search', async (req, res) => {
    const keyword = req.query.keyword;
    if (!keyword) {
        return res.status(400).json({ error: 'Keyword parameter is missing' });
    }
    try {
        const results = await ytSearch(keyword);
        const formattedResults = results.videos.slice(0, 10).map(video => ({
            title: video.title,
            videoId: video.videoId,
            thumbnail: video.thumbnail,
            duration: video.timestamp,
        }));

        res.json(formattedResults);
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});


function getValidFileName(fileName) {
    const invalidChars = /[<>:"\/\\|?*\x00-\x1F]/g;
    let sanitizedBaseName = fileName.replace(invalidChars, "_").trim();
    if (!sanitizedBaseName) {
        sanitizedBaseName = "youtube";
    }
    return sanitizedBaseName;
}







app.post("/", async (req, res) => {
    const { url, videoQuality } = req.body;

    if (!url) {
        return res.status(400).json({ error: "Video URL is required!" });
    }
    if (!isYouTubeURL(url)) {
        return res.status(400).json({ error: "Not a valid YouTube URL!" });
    }

    let domain = process.env.DOMAIN;
    let proxyUrl = `http://${await getNextWorkingProxy()}`;
    
    let format = videoQuality ? "mp4" : "mp3";
    let payload = { url, format, proxyUrl };
    let data = { status: "tunnel" };

    try {
        let titleData = await fetchVideoTitle(url);

        let title = titleData.length > 0 
            ? titleData[0].title 
            : (await getVideoTitle(url, proxyUrl)).title;

        let filename = `${getValidFileName(title)}.${format}`;
        payload.filename = filename;
        data.filename = filename;

        data.url = `${domain}/dl/${jwt.sign(payload, process.env.SECRET_KEY, { expiresIn: "1h" })}`;
        return res.json(data);

    } catch (error) {
        console.error("Error fetching video title:", error);
        return res.status(400).json({ error: error.data || error.message });
    }
});



const sanitizeFilename = (filename) => {
    return filename.replace(/[/\\?%*:|"<>]/g, "_").trim();
};

const downloadWithRetry = async (req, res, retryCount = 0) => {
    let extractedData = decodeToken(req.params.hash);    
    if (!extractedData) {
        return res.status(400).send("<h1>URL is invalid or expired!</h1>");
    }
    const logs = readLogs();
    const clientCountry = req.clientCountry;
    let { url, proxyUrl, filename, format } = extractedData;
    const ytDlpWrap = new YTDlpWrap(ytDlpPath);
    const passThrough = new PassThrough();
    const sanitizedFilename = sanitizeFilename(filename);
    const encodedFilename = encodeURIComponent(sanitizedFilename);
    if (!logs.includes(req.params.hash)) {
        logs.push(req.params.hash);
        writeLogs(logs);
        io.emit("console",{
            message: `
            <div style="display: inline-block;border: 2px double #A66E38;color:white;padding:5px;">
                <p>Country: \t${clientCountry}</p>
                <p>IP: \t${req.clientIp}</p>
                <p>File Name: \t${filename}</p>
            </div>
            `
        });
    }  

    let options = [
        '--proxy', proxyUrl,
        url,
        '--no-part'
    ];
    if (format === "mp4") {
        options.push("-f", "best[ext=mp4]", '--ffmpeg-location', ffmpegPath);
        res.setHeader("Content-Disposition", `attachment; filename="${encodedFilename}"`);
        res.setHeader("Content-Type", "video/mp4");
    } else {
        options.push('-f', 'bestaudio[ext=m4a]/bestaudio[ext=webm]', '--ffmpeg-location', ffmpegPath);
        res.setHeader("Content-Disposition", `attachment; filename="${encodedFilename}"`);
        res.setHeader("Content-Type", "audio/webm");
    }
    try {
        console.log(`Attempt ${retryCount + 1}: Downloading with proxy ${proxyUrl}`);
        const stream = ytDlpWrap.execStream(options);
        stream.pipe(passThrough);
        passThrough.pipe(res);
    } catch (error) {
        await Proxy.update(
            { status: "unchecked" },
            { where: { address: removeHttp(proxyUrl) } }
        );
        resetProxyCache();
        console.error("Error downloading file:", error);

        if (retryCount < 20) {
            console.log(`Retrying with a new proxy (Attempt ${retryCount + 2})...`);
            proxyUrl = `http://${await getNextWorkingProxy()}`;
            return downloadWithRetry(req, res, retryCount + 1);
        } else {
            return res.status(500).send("<h1>Failed to process the request after multiple attempts.</h1>");
        }
    }
};

app.get("/dl/:hash", (req, res) => {
    downloadWithRetry(req, res);
});







app.use('/admin/panel', function checkAdminSession(req, res, next) {
    if (req.session.admin) {
        return next();
    } else {
        res.redirect('/admin-panel-login');
    }
});



app.get('/admin-panel-login', csrfProtection, (req, res) => {

    if (req.session.admin) {
        res.redirect('/admin/panel/home');
    } else {
        res.render('login', { csrfToken: req.csrfToken() });
    }
});

app.post('/admin-panel-login', csrfProtection, async (req, res) => {
    const { email, password } = req.body;

    try {
        const admin = await Admin.findOne({ where: { email } });
        if (admin) {
            if (password === admin.password) {
                req.session.admin = true;
                return res.redirect('/admin/panel/home');
            }
        }
        res.status(401).send('Invalid email or password');
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});


app.get('/admin/panel/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/admin-panel-login');
});


app.get('/admin/panel/home', async (req, res) => {
    res.render('index');
});

app.get('/admin/panel/account', async (req, res) => {
    const admin = await Admin.findOne();
    res.render('account', { data: admin });
});

app.post('/admin/panel/account', async (req, res) => {
    const { email, password } = req.body;
    const admin = await Admin.findOne();
    admin.email = email;
    admin.password = password;
    await admin.save();
    res.redirect('/admin/panel/account');
});


app.get('/admin/panel/iframes', async (req, res) => {
    const iframes = await Iframe.findAll()
    res.render('admin-iframes', { data: iframes });
});

app.get('/admin/panel/iframes/delete/:id', async (req, res) => {
    try {
        const iframeId = req.params.id;
        await Iframe.destroy({ where: { id: iframeId } });
        resetProxyCache()
        res.redirect('/admin/panel/iframes');
    } catch (error) {
        console.log(error);
        res.status(500).send('Error deleting iframe');
    }
});

app.get('/admin/panel/iframes/:id', async (req, res) => {
    try {
        const iframeId = req.params.id;
        const iframe = await Iframe.findByPk(iframeId);
        if (iframe) {
            res.json({ success: true, iframe });
        } else {
            res.json({ success: false, message: 'Iframe not found' });
        }
    } catch (error) {
        console.error('Error fetching iframe:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});



app.post('/admin/panel/iframes/edit', async (req, res) => {
    try {
        const { id, slug, ad_code } = req.body;
        await Iframe.update(
            { slug, ad_code: ad_code || null },
            { where: { id } }
        );
        res.redirect('/admin/panel/iframes');
    } catch (error) {
        console.error('Error updating iframe:', error);
        res.status(500).send('Error updating iframe');
    }
});


app.post('/admin/panel/iframes/add', async (req, res) => {
    const { slug, ad_code } = req.body;
    try {
        await Iframe.create({ slug, ad_code });
        res.json({ success: true });
    } catch (error) {
        console.error('Error adding iframe:', error);
        res.json({ success: false, message: 'Failed to add iframe.' });
    }
});


app.post("/teting", async (req, res) => {
    res.json({
        proxies: await Proxy.findAll(),
        admin: await Admin.findOne()
    })
})

app.get('/admin/panel/proxies', async (req, res) => {
    const proxies = await Proxy.findAll();
    const totalProxies = proxies.length;
    const totalWorking = proxies.filter(proxy => proxy.status === 'working').length;
    const totalBlocked = proxies.filter(proxy => proxy.status === 'blocked').length;
    const totalUnchecked = proxies.filter(proxy => !proxy.status || proxy.status === 'unchecked').length;

    res.render('proxies', {
        data: {
            proxies,
            totalProxies,
            totalWorking,
            totalBlocked,
            totalUnchecked
        }
    });
});

app.delete('/admin/panel/proxies/delete/:id', async (req, res) => {
    const { id } = req.params;

    try {
        await Proxy.destroy({ where: { id } });
        resetProxyCache()
        res.json({ success: true, message: 'Proxy deleted successfully!' });
    } catch (error) {
        res.json({ success: false, message: 'Failed to delete proxy.' });
    }
});


app.put('/admin/panel/proxies/edit/:id', async (req, res) => {
    const { id } = req.params;
    const { address } = req.body;

    try {
        // Update the address and set status to 'unchecked'
        await Proxy.update(
            { address, status: 'unchecked' }, // Set both fields
            { where: { id } }
        );

        res.json({ success: true, message: 'Proxy updated successfully and status set to unchecked!' });
    } catch (error) {
        console.log('Error updating proxy:', error);
        res.json({ success: false, message: 'Failed to update proxy.' });
    }
});




app.post("/admin/panel/proxies/delete", async (req, res) => {
    try {
        const { type } = req.body;
        let whereCondition = {};

        if (type !== "all") {
            whereCondition.status = type;
        }

        await Proxy.destroy({ where: whereCondition });
        res.json({ success: true, message: "Proxies deleted successfully!" });
    } catch (error) {
        res.json({ success: false, message: "Error deleting proxies!" });
    }
});


app.get("/admin/panel/proxies/export/:type", async (req, res) => {
    try {
        const { type } = req.params;
        let whereCondition = {};

        if (type !== "all") {
            whereCondition.status = type;
        }

        const proxies = await Proxy.findAll({ where: whereCondition });

        const filePath = path.join(__dirname, "proxies.txt");
        fs.writeFileSync(filePath, proxies.map(proxy => proxy.address).join("\n"));

        res.download(filePath, "proxies.txt", () => {
            fs.unlinkSync(filePath);
        });
    } catch (error) {
        res.status(500).send("Error exporting proxies!");
    }
});



app.get("/admin/panel/reset/logs", (req, res) => {
    writeLogs([]);
    res.redirect("/admin/panel/proxies");
})


app.get('/admin/panel/console', async (req, res) => {
    res.render('console');
});





// Start the HTTP server
server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

// Handle errors related to PORT
server.on('error', (error) => {
    if (error.syscall !== 'listen') {
        throw error;
    }

    // Handle specific listen errors with friendly messages
    switch (error.code) {
        case 'EACCES':
            console.error(`Port ${PORT} requires elevated privileges`);
            process.exit(1);
            break;
        case 'EADDRINUSE':
            console.error(`Port ${PORT} is already in use`);
            process.exit(1);
            break;
        default:
            throw error;
    }
});
