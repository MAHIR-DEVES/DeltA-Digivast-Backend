// src/app.ts
import express from "express";

// src/app/routes/index.ts
import { Router as Router2 } from "express";

// src/app/modules/user/user.route.ts
import { Router } from "express";

// src/app/config/env.ts
import dotenv from "dotenv";
dotenv.config();
var requiredEnvVars = ["NODE_ENV", "PORT", "DATABASE_URL", "JWT_SECRET"];
requiredEnvVars.forEach((varName) => {
  if (!process.env[varName]) {
    throw new Error(
      `Environment variable ${varName} is required but not set in .env file.`
    );
  }
});
var loadEnvVariables = () => {
  return {
    NODE_ENV: process.env.NODE_ENV,
    PORT: process.env.PORT,
    DATABASE_URL: process.env.DATABASE_URL,
    JWT_SECRET: process.env.JWT_SECRET
  };
};
var envVars = loadEnvVariables();

// src/app/lib/prisma.ts
import "dotenv/config";
import { PrismaPg } from "@prisma/adapter-pg";

// src/generated/prisma/client.ts
import * as path from "path";
import { fileURLToPath } from "url";

// src/generated/prisma/internal/class.ts
import * as runtime from "@prisma/client/runtime/client";
var config = {
  "previewFeatures": [],
  "clientVersion": "7.4.2",
  "engineVersion": "94a226be1cf2967af2541cca5529f0f7ba866919",
  "activeProvider": "postgresql",
  "inlineSchema": '// Role enum: employee permission control\nenum Role {\n  ADMIN\n  MANAGER\n  EMPLOY\n}\n\n// Role enum: employee permission control\nenum STATUS {\n  ACTIVE\n  BLOCK\n}\n\n// Designation enum: employee position\nenum Designation {\n  VIDEO_EDITOR\n  GRAPHIC_DESIGNER\n  WEB_DEVELOPER\n  UI_UX_DESIGNER\n}\n\n// This is your Prisma schema file,\n// learn more about it in the docs: https://pris.ly/d/prisma-schema\n\n// Looking for ways to speed up your queries, or scale easily with your serverless or edge functions?\n// Try Prisma Accelerate: https://pris.ly/cli/accelerate-init\n\ngenerator client {\n  provider = "prisma-client"\n  output   = "../../src/generated/prisma"\n}\n\ndatasource db {\n  provider = "postgresql"\n}\n\n// Employee/User model\nmodel User {\n  id          String       @id @default(uuid())\n  name        String\n  email       String       @unique\n  password    String\n  phone       String?\n  photoUrl    String?\n  role        Role         @default(EMPLOY)\n  designation Designation?\n\n  // Optional job info\n  skills     String? // comma separated or JSON string\n  experience Int? // years of experience\n  department String? // e.g., "Design", "Development"\n\n  // Tracking fields\n  status    STATUS    @default(ACTIVE) // ACTIVE, INACTIVE, ON_LEAVE\n  createdAt DateTime  @default(now())\n  updatedAt DateTime  @updatedAt\n  lastLogin DateTime? // track employee last login\n}\n',
  "runtimeDataModel": {
    "models": {},
    "enums": {},
    "types": {}
  },
  "parameterizationSchema": {
    "strings": [],
    "graph": ""
  }
};
config.runtimeDataModel = JSON.parse('{"models":{"User":{"fields":[{"name":"id","kind":"scalar","type":"String"},{"name":"name","kind":"scalar","type":"String"},{"name":"email","kind":"scalar","type":"String"},{"name":"password","kind":"scalar","type":"String"},{"name":"phone","kind":"scalar","type":"String"},{"name":"photoUrl","kind":"scalar","type":"String"},{"name":"role","kind":"enum","type":"Role"},{"name":"designation","kind":"enum","type":"Designation"},{"name":"skills","kind":"scalar","type":"String"},{"name":"experience","kind":"scalar","type":"Int"},{"name":"department","kind":"scalar","type":"String"},{"name":"status","kind":"enum","type":"STATUS"},{"name":"createdAt","kind":"scalar","type":"DateTime"},{"name":"updatedAt","kind":"scalar","type":"DateTime"},{"name":"lastLogin","kind":"scalar","type":"DateTime"}],"dbName":null}},"enums":{},"types":{}}');
config.parameterizationSchema = {
  strings: JSON.parse('["where","User.findUnique","User.findUniqueOrThrow","orderBy","cursor","User.findFirst","User.findFirstOrThrow","User.findMany","data","User.createOne","User.createMany","User.createManyAndReturn","User.updateOne","User.updateMany","User.updateManyAndReturn","create","update","User.upsertOne","User.deleteOne","User.deleteMany","having","_count","_avg","_sum","_min","_max","User.groupBy","User.aggregate","AND","OR","NOT","id","name","email","password","phone","photoUrl","Role","role","Designation","designation","skills","experience","department","STATUS","status","createdAt","updatedAt","lastLogin","equals","in","notIn","lt","lte","gt","gte","not","contains","startsWith","endsWith","set","increment","decrement","multiply","divide"]'),
  graph: "SwsQEhwAADUAMB0AAAQAEB4AADUAMB8BAAAAASABADYAISEBAAAAASIBADYAISMBADcAISQBADcAISYAADgmIigAADkoIykBADcAISoCADoAISsBADcAIS0AADstIi5AADwAIS9AADwAITBAAD0AIQEAAAABACABAAAAAQAgEhwAADUAMB0AAAQAEB4AADUAMB8BADYAISABADYAISEBADYAISIBADYAISMBADcAISQBADcAISYAADgmIigAADkoIykBADcAISoCADoAISsBADcAIS0AADstIi5AADwAIS9AADwAITBAAD0AIQcjAAA-ACAkAAA-ACAoAAA-ACApAAA-ACAqAAA-ACArAAA-ACAwAAA-ACADAAAABAAgAwAABQAwBAAAAQAgAwAAAAQAIAMAAAUAMAQAAAEAIAMAAAAEACADAAAFADAEAAABACAPHwEAAAABIAEAAAABIQEAAAABIgEAAAABIwEAAAABJAEAAAABJgAAACYCKAAAACgDKQEAAAABKgIAAAABKwEAAAABLQAAAC0CLkAAAAABL0AAAAABMEAAAAABAQgAAAkAIA8fAQAAAAEgAQAAAAEhAQAAAAEiAQAAAAEjAQAAAAEkAQAAAAEmAAAAJgIoAAAAKAMpAQAAAAEqAgAAAAErAQAAAAEtAAAALQIuQAAAAAEvQAAAAAEwQAAAAAEBCAAACwAwAQgAAAsAMA8fAQBEACEgAQBEACEhAQBEACEiAQBEACEjAQBFACEkAQBFACEmAABGJiIoAABHKCMpAQBFACEqAgBIACErAQBFACEtAABJLSIuQABKACEvQABKACEwQABLACECAAAAAQAgCAAADgAgDx8BAEQAISABAEQAISEBAEQAISIBAEQAISMBAEUAISQBAEUAISYAAEYmIigAAEcoIykBAEUAISoCAEgAISsBAEUAIS0AAEktIi5AAEoAIS9AAEoAITBAAEsAIQIAAAAEACAIAAAQACACAAAABAAgCAAAEAAgAwAAAAEAIA8AAAkAIBAAAA4AIAEAAAABACABAAAABAAgDBUAAD8AIBYAAEAAIBcAAEMAIBgAAEIAIBkAAEEAICMAAD4AICQAAD4AICgAAD4AICkAAD4AICoAAD4AICsAAD4AIDAAAD4AIBIcAAAaADAdAAAXABAeAAAaADAfAQAbACEgAQAbACEhAQAbACEiAQAbACEjAQAcACEkAQAcACEmAAAdJiIoAAAeKCMpAQAcACEqAgAfACErAQAcACEtAAAgLSIuQAAhACEvQAAhACEwQAAiACEDAAAABAAgAwAAFgAwFAAAFwAgAwAAAAQAIAMAAAUAMAQAAAEAIBIcAAAaADAdAAAXABAeAAAaADAfAQAbACEgAQAbACEhAQAbACEiAQAbACEjAQAcACEkAQAcACEmAAAdJiIoAAAeKCMpAQAcACEqAgAfACErAQAcACEtAAAgLSIuQAAhACEvQAAhACEwQAAiACEOFQAAJwAgGAAANAAgGQAANAAgMQEAAAABMgEAAAAEMwEAAAAENAEAAAABNQEAAAABNgEAAAABNwEAAAABOAEAMwAhOQEAAAABOgEAAAABOwEAAAABDhUAACQAIBgAADIAIBkAADIAIDEBAAAAATIBAAAABTMBAAAABTQBAAAAATUBAAAAATYBAAAAATcBAAAAATgBADEAITkBAAAAAToBAAAAATsBAAAAAQcVAAAnACAYAAAwACAZAAAwACAxAAAAJgIyAAAAJggzAAAAJgg4AAAvJiIHFQAAJAAgGAAALgAgGQAALgAgMQAAACgDMgAAACgJMwAAACgJOAAALSgjDRUAACQAIBYAACwAIBcAACQAIBgAACQAIBkAACQAIDECAAAAATICAAAABTMCAAAABTQCAAAAATUCAAAAATYCAAAAATcCAAAAATgCACsAIQcVAAAnACAYAAAqACAZAAAqACAxAAAALQIyAAAALQgzAAAALQg4AAApLSILFQAAJwAgGAAAKAAgGQAAKAAgMUAAAAABMkAAAAAEM0AAAAAENEAAAAABNUAAAAABNkAAAAABN0AAAAABOEAAJgAhCxUAACQAIBgAACUAIBkAACUAIDFAAAAAATJAAAAABTNAAAAABTRAAAAAATVAAAAAATZAAAAAATdAAAAAAThAACMAIQsVAAAkACAYAAAlACAZAAAlACAxQAAAAAEyQAAAAAUzQAAAAAU0QAAAAAE1QAAAAAE2QAAAAAE3QAAAAAE4QAAjACEIMQIAAAABMgIAAAAFMwIAAAAFNAIAAAABNQIAAAABNgIAAAABNwIAAAABOAIAJAAhCDFAAAAAATJAAAAABTNAAAAABTRAAAAAATVAAAAAATZAAAAAATdAAAAAAThAACUAIQsVAAAnACAYAAAoACAZAAAoACAxQAAAAAEyQAAAAAQzQAAAAAQ0QAAAAAE1QAAAAAE2QAAAAAE3QAAAAAE4QAAmACEIMQIAAAABMgIAAAAEMwIAAAAENAIAAAABNQIAAAABNgIAAAABNwIAAAABOAIAJwAhCDFAAAAAATJAAAAABDNAAAAABDRAAAAAATVAAAAAATZAAAAAATdAAAAAAThAACgAIQcVAAAnACAYAAAqACAZAAAqACAxAAAALQIyAAAALQgzAAAALQg4AAApLSIEMQAAAC0CMgAAAC0IMwAAAC0IOAAAKi0iDRUAACQAIBYAACwAIBcAACQAIBgAACQAIBkAACQAIDECAAAAATICAAAABTMCAAAABTQCAAAAATUCAAAAATYCAAAAATcCAAAAATgCACsAIQgxCAAAAAEyCAAAAAUzCAAAAAU0CAAAAAE1CAAAAAE2CAAAAAE3CAAAAAE4CAAsACEHFQAAJAAgGAAALgAgGQAALgAgMQAAACgDMgAAACgJMwAAACgJOAAALSgjBDEAAAAoAzIAAAAoCTMAAAAoCTgAAC4oIwcVAAAnACAYAAAwACAZAAAwACAxAAAAJgIyAAAAJggzAAAAJgg4AAAvJiIEMQAAACYCMgAAACYIMwAAACYIOAAAMCYiDhUAACQAIBgAADIAIBkAADIAIDEBAAAAATIBAAAABTMBAAAABTQBAAAAATUBAAAAATYBAAAAATcBAAAAATgBADEAITkBAAAAAToBAAAAATsBAAAAAQsxAQAAAAEyAQAAAAUzAQAAAAU0AQAAAAE1AQAAAAE2AQAAAAE3AQAAAAE4AQAyACE5AQAAAAE6AQAAAAE7AQAAAAEOFQAAJwAgGAAANAAgGQAANAAgMQEAAAABMgEAAAAEMwEAAAAENAEAAAABNQEAAAABNgEAAAABNwEAAAABOAEAMwAhOQEAAAABOgEAAAABOwEAAAABCzEBAAAAATIBAAAABDMBAAAABDQBAAAAATUBAAAAATYBAAAAATcBAAAAATgBADQAITkBAAAAAToBAAAAATsBAAAAARIcAAA1ADAdAAAEABAeAAA1ADAfAQA2ACEgAQA2ACEhAQA2ACEiAQA2ACEjAQA3ACEkAQA3ACEmAAA4JiIoAAA5KCMpAQA3ACEqAgA6ACErAQA3ACEtAAA7LSIuQAA8ACEvQAA8ACEwQAA9ACELMQEAAAABMgEAAAAEMwEAAAAENAEAAAABNQEAAAABNgEAAAABNwEAAAABOAEANAAhOQEAAAABOgEAAAABOwEAAAABCzEBAAAAATIBAAAABTMBAAAABTQBAAAAATUBAAAAATYBAAAAATcBAAAAATgBADIAITkBAAAAAToBAAAAATsBAAAAAQQxAAAAJgIyAAAAJggzAAAAJgg4AAAwJiIEMQAAACgDMgAAACgJMwAAACgJOAAALigjCDECAAAAATICAAAABTMCAAAABTQCAAAAATUCAAAAATYCAAAAATcCAAAAATgCACQAIQQxAAAALQIyAAAALQgzAAAALQg4AAAqLSIIMUAAAAABMkAAAAAEM0AAAAAENEAAAAABNUAAAAABNkAAAAABN0AAAAABOEAAKAAhCDFAAAAAATJAAAAABTNAAAAABTRAAAAAATVAAAAAATZAAAAAATdAAAAAAThAACUAIQAAAAAAAAE8AQAAAAEBPAEAAAABATwAAAAmAgE8AAAAKAMFPAIAAAABPQIAAAABPgIAAAABPwIAAAABQAIAAAABATwAAAAtAgE8QAAAAAEBPEAAAAABAAAAAAUVAAYWAAcXAAgYAAkZAAoAAAAAAAUVAAYWAAcXAAgYAAkZAAoBAgECAwEFBgEGBwEHCAEJCgEKDAILDQMMDwENEQIOEgQREwESFAETFQIaGAUbGQs"
};
async function decodeBase64AsWasm(wasmBase64) {
  const { Buffer } = await import("buffer");
  const wasmArray = Buffer.from(wasmBase64, "base64");
  return new WebAssembly.Module(wasmArray);
}
config.compilerWasm = {
  getRuntime: async () => await import("@prisma/client/runtime/query_compiler_fast_bg.postgresql.mjs"),
  getQueryCompilerWasmModule: async () => {
    const { wasm } = await import("@prisma/client/runtime/query_compiler_fast_bg.postgresql.wasm-base64.mjs");
    return await decodeBase64AsWasm(wasm);
  },
  importName: "./query_compiler_fast_bg.js"
};
function getPrismaClientClass() {
  return runtime.getPrismaClient(config);
}

// src/generated/prisma/internal/prismaNamespace.ts
import * as runtime2 from "@prisma/client/runtime/client";
var getExtensionContext = runtime2.Extensions.getExtensionContext;
var NullTypes2 = {
  DbNull: runtime2.NullTypes.DbNull,
  JsonNull: runtime2.NullTypes.JsonNull,
  AnyNull: runtime2.NullTypes.AnyNull
};
var TransactionIsolationLevel = runtime2.makeStrictEnum({
  ReadUncommitted: "ReadUncommitted",
  ReadCommitted: "ReadCommitted",
  RepeatableRead: "RepeatableRead",
  Serializable: "Serializable"
});
var defineExtension = runtime2.Extensions.defineExtension;

// src/generated/prisma/enums.ts
var Role = {
  ADMIN: "ADMIN",
  MANAGER: "MANAGER",
  EMPLOY: "EMPLOY"
};

// src/generated/prisma/client.ts
globalThis["__dirname"] = path.dirname(fileURLToPath(import.meta.url));
var PrismaClient = getPrismaClientClass();

// src/app/lib/prisma.ts
var connectionString = envVars.DATABASE_URL;
var adapter = new PrismaPg({ connectionString });
var prisma = new PrismaClient({ adapter });

// src/app/modules/user/user.service.ts
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
var registerUser = async (payload) => {
  const hashedPassword = await bcrypt.hash(payload.password, 10);
  const user = await prisma.user.create({
    data: {
      ...payload,
      password: hashedPassword
    },
    select: {
      id: true,
      name: true,
      email: true,
      phone: true,
      photoUrl: true,
      role: true,
      designation: true,
      skills: true,
      experience: true,
      department: true,
      status: true,
      createdAt: true,
      updatedAt: true,
      lastLogin: true
    }
  });
  return user;
};
var loginUser = async (payload) => {
  const { email, password } = payload;
  const user = await prisma.user.findUnique({
    where: { email }
  });
  if (!user) {
    throw new Error("User not found");
  }
  const isPasswordMatched = await bcrypt.compare(password, user.password);
  if (!isPasswordMatched) {
    throw new Error("Invalid password");
  }
  const token = jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      name: user.name,
      phone: user.phone,
      photoUrl: user.photoUrl,
      designation: user.designation,
      skills: user.skills,
      experience: user.experience,
      department: user.department,
      status: user.status
    },
    envVars.JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
  const { password: _, ...userWithoutPassword } = user;
  return {
    accessToken: token,
    user: userWithoutPassword
  };
};
var getAllUsers = async () => {
  const users = await prisma.user.findMany();
  return users;
};
var deleteUser = async (id) => {
  const user = await prisma.user.delete({
    where: { id }
  });
  return user;
};
var UseService = {
  registerUser,
  deleteUser,
  getAllUsers,
  loginUser
};

// src/app/shared/catchAsync.ts
var catchAsync = (fn) => {
  return async (req, res, next) => {
    try {
      await fn(req, res, next);
    } catch (error) {
      next(error);
    }
  };
};

// src/app/shared/sendResponse.ts
var sendResponse = (res, responseData) => {
  const { httpStatusCode, success, message, data } = responseData;
  res.status(httpStatusCode).json({
    success,
    message,
    data
  });
};

// src/app/modules/user/user.controller.ts
var registerUser2 = catchAsync(async (req, res) => {
  const payload = req.body;
  const result = await UseService.registerUser(payload);
  sendResponse(res, {
    httpStatusCode: 201,
    success: true,
    message: "user created successfully",
    data: result
  });
});
var loginUser2 = catchAsync(async (req, res) => {
  const result = await UseService.loginUser(req.body);
  sendResponse(res, {
    httpStatusCode: 200,
    success: true,
    message: "Login successful",
    data: result
  });
});
var getAllUsers2 = catchAsync(async (req, res) => {
  const result = await UseService.getAllUsers();
  sendResponse(res, {
    httpStatusCode: 200,
    success: true,
    message: "user fetched successfully",
    data: result
  });
});
var deleteUser2 = catchAsync(async (req, res) => {
  const { id } = req.params;
  const result = await UseService.deleteUser(id);
  sendResponse(res, {
    httpStatusCode: 200,
    success: true,
    message: "user delete successfully",
    data: result
  });
});
var UserController = {
  registerUser: registerUser2,
  getAllUsers: getAllUsers2,
  deleteUser: deleteUser2,
  loginUser: loginUser2
};

// src/app/middleware/auth.ts
import jwt2 from "jsonwebtoken";
var auth = (...requiredRoles) => {
  return (req, res, next) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({
          success: false,
          message: "You are not authorized"
        });
      }
      const token = authHeader.split(" ")[1];
      if (!token) {
        return res.status(401).json({
          success: false,
          message: "Invalid token format"
        });
      }
      const verifiedUser = jwt2.verify(token, envVars.JWT_SECRET);
      if (requiredRoles.length && !requiredRoles.includes(verifiedUser.role)) {
        return res.status(403).json({
          success: false,
          message: "Forbidden access"
        });
      }
      req.user = verifiedUser;
      next();
    } catch (error) {
      next(error);
    }
  };
};

// src/app/modules/user/user.route.ts
var router = Router();
router.post("/", auth(Role.ADMIN), UserController.registerUser);
router.post("/login", UserController.loginUser);
router.get("/", auth(Role.ADMIN, Role.MANAGER), UserController.getAllUsers);
router.delete("/:id", auth(Role.ADMIN), UserController.deleteUser);
var UserRoute = router;

// src/app/routes/index.ts
var router2 = Router2();
router2.use("/users", UserRoute);
var IndexRoutes = router2;

// src/app/middleware/golbelErrorHandler.ts
import status from "http-status";
var globalErrorHandler = (err, req, res, next) => {
  if (envVars.NODE_ENV === "development") {
    console.log("Error From Global Error Handler:", err);
  }
  let statusCode = status.INTERNAL_SERVER_ERROR;
  let message = "Internal Server Error";
  res.status(statusCode).json({
    success: false,
    message,
    error: err.message
  });
};

// src/app/middleware/notFound.ts
import status2 from "http-status";
var notFound = (req, res) => {
  res.status(status2.NOT_FOUND).json({
    success: false,
    message: `Route ${req.originalUrl} not found`
  });
};

// src/app.ts
var app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use("/api/v1", IndexRoutes);
app.get("/", (req, res) => {
  res.status(200).json({
    message: "Server is running"
  });
});
app.use(globalErrorHandler);
app.use(notFound);
var app_default = app;

// src/server.ts
var bootstrap = () => {
  try {
    app_default.listen(envVars.PORT, () => {
      console.log(`\u{1F680} Server is running on http://localhost:${envVars.PORT}`);
    });
  } catch (error) {
    console.log(error);
  }
};
bootstrap();
