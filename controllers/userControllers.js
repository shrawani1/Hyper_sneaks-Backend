
const userModel = require('../models/userModel');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sendOtp = require('../service/sendOtp');
const crypto = require('crypto');
const sendEmail = require('../service/emailServices');
const PASSWORD_POLICY = {
  minLength: 8,
  maxLength: 20,
  regex: /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
};
 
// Track reused passwords and expiry
const PASSWORD_HISTORY_LIMIT = 5; // Number of previous passwords to store
const PASSWORD_EXPIRY_DAYS = 90; // Password expiry in days
 
// Function to validate password strength
const isPasswordValid = (password) => {
  if (
    password.length < PASSWORD_POLICY.minLength ||
    password.length > PASSWORD_POLICY.maxLength ||
    !PASSWORD_POLICY.regex.test(password)
  ) {
    return false;
  }
  return true;
};
 
// const createUser = async (req, res) => {
//     // res.send("Create user API is working!")

//     //1.Check incoming data
//     console.log(req.body);

//     //2.Destructure the incoming data
//     const { firstName, lastName, email, phone, password } = req.body;

//     //3.Validate the data
//     if (!firstName || !lastName || !email || !password || !phone) {
//         // res.send("Please enter all fields!")
//         res.status(400).json({
//             "success": false,
//             "message": "Please enter all fields!"
//         });
//         return;
//     }

//     //4.Error Handling(try catch)
//     try {
//         //5.Check if the user is already registered
//         const existingUser = await userModel.findOne({ email: email });
//         //5.1 If user found: send response
//         if (existingUser) {
//             return res.json({
//                 "success": false,
//                 "message": "User already exists!"
//             });
//         }

//         // Hashing / encryption of the password
//         const randomSalt = await bcrypt.genSalt(10);
//         const hashedPassword = await bcrypt.hash(password, randomSalt);

//         //5.2 If user is new:

//         const newUser = new userModel({
//             //Field : Client's Value
//             firstName: firstName,
//             lastName: lastName,
//             email: email,
//             phone: phone,
//             password: hashedPassword
//         });

//         //Save to database
//         await newUser.save();

//         //send the response
//         res.status(201).json({
//             "success": true,
//             "message": "User Created Successfully!"
//         });
//     } catch (error) {
//         console.log(error);
//         res.status(400).json({
//             "success": false,
//             "message": "Internal server Error!"
//         });
//     }
// };
const createUser = async (req, res) => {
  // Log incoming request data (optional, useful for debugging)
  console.log("Incoming Request Data:", req.body);
 
  const { firstName, lastName, email, phone, password } = req.body;
 
  // Check for missing fields
  if (!firstName || !lastName || !email || !phone || !password) {
    return res.status(400).json({
      success: false,
      message: "Please enter all fields!",
    });
  }
 
  // Validate password strength
  if (!isPasswordValid(password)) {
    return res.status(400).json({
      success: false,
      message:
        "Password must be 8-20 characters long, include uppercase, lowercase, numbers, and special characters!",
    });
  }
 
  try {
    const existingUser = await userModel.findOne({ email });
 
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists!",
      });
    }
 
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
 
    // Generate email verification token
    const verificationToken = crypto.randomBytes(20).toString("hex");
    const hashedToken = crypto.createHash("sha256").update(verificationToken).digest("hex");
 
    const newUser = new userModel({
      firstName,
      lastName,
      email,
      phone,
      password: hashedPassword,
      passwordHistory: [hashedPassword], // Add initial password to history
      passwordLastChanged: new Date(), // Record the password change date
      isEmailVerified: false, // Initialize email verification status
      emailVerificationToken: hashedToken, 
      emailVerificationTokenExpire: Date.now() + 10 * 60 * 1000, 
    });
 
    await newUser.save();
 
    // Log email before sending (optional)
    console.log("Sending verification email to:", newUser.email);
 
    if (!newUser.email) {
      console.error("Error: Email is missing in newUser");
    } else {
      const verificationURL = `${process.env.FRONTEND_URL || "https://localhost:3000"}/verify-email/${verificationToken}`;
      const message = `Please click on the link to verify your email: \n\n ${verificationURL}`;
 
      await sendEmail({
        email: newUser.email,
        subject: "Email Verification",
        message,
      });
    }
 
    res.status(201).json({
      success: true,
      message: "User registered successfully! Verification email sent.",
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Internal Server Error!",
    });
  }
};


//login function
const loginUser = async (req, res) => {
    // res.send("Login API is working !")

    //Check incoming data
    console.log(req.body);

    //Destructuring the data
    const { email, password } = req.body;

    //Validation
    if (!email || !password) {
        return res.json({
            "success": false,
            "message": "Please enter all fields!"
        });
    }

    //try catch
    try {

        //find user (email)
        const user = await userModel.findOne({ email: email });
        

        //not found(error message)
        if (!user) {
            return res.status(400).json({
                "success": false,
                "message": "User does not exist!"
            });
        }

        //compare password(bcrypt)
        const isValidPassword = await bcrypt.compare(password, user.password);

        //not valid(error)
        if (!isValidPassword) {
            return res.status(400).json({
                "success": false,
                "message": "Password not matched!"
            });
        }
        //token(Generate - user Data+KEY)
        const token = await jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET
        );
        //response (token, user data)
        res.status(201).json({
            "success": true,
            "message": "User logged in successfully!",
            "token": token,
            "userData": user
        });


    } catch (error) {
        console.log(error);
        return res.status(400).json({
            "success": false,
            "message": "Please enter all fields!"
        });
    }
};


const forgotPassword = async (req, res) => {
    console.log(req.body);
   
    const { phone } = req.body;
   
    if (!phone) {
      return res.status(400).json({
        success: false,
        message: "Please enter your phone number",
      });
    }
    try {
      const user = await userModel.findOne({ phone: phone });
      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }
      // Generate OTP
      const randomOTP = Math.floor(100000 + Math.random() * 900000);
      console.log(randomOTP);
   
      user.resetPasswordOTP = randomOTP;
      user.resetPasswordExpires = Date.now() + 600000; // 10 minutes
      await user.save();
   
      // Send OTP to user phone number
      const isSent = await sendOtp(phone, randomOTP);
   
      if (!isSent) {
        return res.status(400).json({
          success: false,
          message: "Error in sending OTP",
        });
      }
   
      res.status(200).json({
        success: true,
        message: "OTP sent to your phone number",
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        success: false,
        message: "Internal server error",
      });
    }
  };

//verify otp and change password
const verifyOtpAndSetPassword = async (req, res) => {
    //get data
    const { phone, otp, newPassword } = req.body;
    if (!phone || !otp || !newPassword) {
        return res.status(400).json({
            'success': false,
            'message': 'required fields are missing!'
        });
    }
    try {
        const user = await userModel.findOne({ phone: phone });

        //verify otp
        if (user.resetPasswordOTP != otp) {
            return res.status(400).json({
                'success': false,
                'message': 'invalid otp!!'
            });
        }
        if (user.resetPasswordExpires < Date.now()) {
            return res.status(400).json({
                'success': false,
                'message': 'OTP Expired!'
            });
        }
        //password hash
        const randomSalt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, randomSalt);

        //update password
        user.password = hashedPassword;
        await user.save();

        //response
        res.status(200).json({
            'success': true,
            'message': 'OTP verified and password updated!'
        });

    } catch (error) {
        console.log(error);
        return res.status(500).json({
            'success': false,
            'message': 'server error!'
        });
    }
};
const getUserProfile = async (req, res) => {
    const token = req.headers.authorization.split(' ')[1]; // Assuming Bearer token
    if (!token) {
        return res.status(401).json({ message: 'Authorization token is missing' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await userModel.findById(decoded.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
};

const updateUserProfile = async (req, res) => {
    const token = req.headers.authorization.split(' ')[1]; // Assuming Bearer token
    if (!token) {
        return res.status(401).json({ message: 'Authorization token is missing' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await userModel.findById(decoded.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const { firstName, lastName, phone, password } = req.body;
        if (firstName) user.firstName = firstName;
        if (lastName) user.lastName = lastName;
        if (phone) user.phone = phone;
        if (password) user.password = await bcrypt.hash(password, 10);

        await user.save();
        res.json(user);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
};
const getUserDetails = async (req, res) => {
    try {
      const userId = req.params.id; // Assume you have user ID available in params
      const user = await User.findById(userId).select('firstName, lastName, phone');
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      res.json(user);
    } catch (error) {
      res.status(500).json({ message: 'Server error', error });
    }
  };
  
  // Get User Token
const getToken = async (req, res) => {
  try {
    console.log(req.body);
    const { id } = req.body;
 
    const user = await userModel.findById(id);
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'User not found',
      });
    }
 
    const jwtToken = await jwt.sign(
      { id: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET,
      (options = {
        expiresIn:
          Date.now() + process.env.JWT_TOKEN_EXPIRE * 24 * 60 * 60 * 1000 ||
          '1d',
      })
    );
 
    return res.status(200).json({
      success: true,
      message: 'Token generated successfully!',
      token: jwtToken,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: 'Internal Server Error',
      error: error,
    });
  }
};
//Get Current Profile
const getCurrentProfile = async (req, res) => {
  // const id = req.user.id;
  try {
    const token = req.headers.authorization.split(" ")[1];
    const decoded =jwt.verify(token,process.env.JWT_SECRET);
   
    const user = await userModel.findById(decoded.id);
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'User not found',
      });
    }
    res.status(200).json({
      success: true,
      message: 'User fetched successfully',
      user: user,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error,
    });
  }
};

const verifyEmail = async (req, res) => {
  try {
      const token = req.params.token;
 
      // Hash the received token to compare with the stored one
      const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
 
      // Find the user with the matching token and ensure it hasn't expired
      const user = await userModel.findOne({
          emailVerificationToken: hashedToken,
          emailVerificationTokenExpire: { $gt: Date.now() }, // Ensure the token hasn't expired
      });
 
      if (!user) {
          return res.json({ success: false, message: "Invalid or expired token" });
      }
 
      // Mark the user's email as verified
      user.isEmailVerified = true;
      user.emailVerificationToken = undefined; // Clear the token fields
      user.emailVerificationTokenExpire = undefined;
 
      await user.save();
 
      res.json({ success: true, message: "Email verified successfully" });
  } catch (error) {
      console.error("Verification Error:", error);
      res.json({ success: false, message: "Server error" });
  }
};

  
  

// Exporting
module.exports = {
    createUser,
    loginUser,
    forgotPassword,
    verifyOtpAndSetPassword,
    getUserProfile,
    updateUserProfile,
    getUserDetails,
    getToken,
    getCurrentProfile,
    verifyEmail
};