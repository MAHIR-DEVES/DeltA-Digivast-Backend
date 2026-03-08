// src/app.ts
import express8 from "express";

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
import cors from "cors";

// src/app/routes/index.ts
import { Router as Router2 } from "express";

// src/app/modules/user/user.route.ts
import { Router } from "express";

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
  "inlineSchema": 'model Attendance {\n  id           String    @id @default(uuid())\n  employeeName String\n  employeeId   String\n  designation  String\n  checkIn      DateTime\n  checkOut     DateTime?\n  createdAt    DateTime  @default(now())\n  updatedAt    DateTime  @updatedAt\n}\n\nmodel Blog {\n  id          String   @id @default(uuid())\n  title       String\n  description String\n  imageUrl    String?\n  createdAt   DateTime @default(now())\n  updatedAt   DateTime @updatedAt\n}\n\nmodel Course {\n  id          String       @id @default(uuid())\n  imageUrl    String\n  title       String\n  category    String\n  instructor  String\n  duration    String\n  price       Float\n  status      CourseStatus @default(DRAFT)\n  description String\n  createdAt   DateTime     @default(now())\n  updatedAt   DateTime     @updatedAt\n}\n\n// Role enum: employee permission control\nenum Role {\n  ADMIN\n  MANAGER\n  EMPLOY\n}\n\n// Role enum: employee permission control\nenum STATUS {\n  ACTIVE\n  BLOCK\n}\n\n// Designation enum: employee position\nenum Designation {\n  VIDEO_EDITOR\n  GRAPHIC_DESIGNER\n  WEB_DEVELOPER\n  UI_UX_DESIGNER\n}\n\nenum CourseStatus {\n  DRAFT\n  PUBLISHED\n  ARCHIVED\n}\n\nmodel Hero {\n  id          String   @id @default(uuid())\n  title       String\n  description String\n  imageUrl    String\n  createdAt   DateTime @default(now())\n  updatedAt   DateTime @updatedAt\n}\n\nmodel Lead {\n  id        String   @id @default(uuid())\n  name      String\n  email     String\n  phone     String?\n  from      String\n  company   String?\n  date      DateTime\n  createdAt DateTime @default(now())\n  updatedAt DateTime @updatedAt\n}\n\nmodel Portfolio {\n  id          String   @id @default(uuid())\n  title       String\n  category    String\n  description String\n  imageUrl    String?\n  videoUrl    String?\n  createdAt   DateTime @default(now())\n  updatedAt   DateTime @updatedAt\n}\n\n// This is your Prisma schema file,\n// learn more about it in the docs: https://pris.ly/d/prisma-schema\n\n// Looking for ways to speed up your queries, or scale easily with your serverless or edge functions?\n// Try Prisma Accelerate: https://pris.ly/cli/accelerate-init\n\ngenerator client {\n  provider = "prisma-client"\n  output   = "../../src/generated/prisma"\n}\n\ndatasource db {\n  provider = "postgresql"\n}\n\n// Employee/User model\nmodel User {\n  id          String       @id @default(uuid())\n  employeeId  String       @unique\n  name        String\n  email       String       @unique\n  password    String\n  phone       String?\n  photoUrl    String?\n  role        Role         @default(EMPLOY)\n  designation Designation?\n\n  // Optional job info\n  skills     String? // comma separated or JSON string\n  experience Int? // years of experience\n  department String? // e.g., "Design", "Development"\n\n  // Tracking fields\n  status    STATUS    @default(ACTIVE) // ACTIVE, INACTIVE, ON_LEAVE\n  createdAt DateTime  @default(now())\n  updatedAt DateTime  @updatedAt\n  lastLogin DateTime? // track employee last login\n}\n',
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
config.runtimeDataModel = JSON.parse('{"models":{"Attendance":{"fields":[{"name":"id","kind":"scalar","type":"String"},{"name":"employeeName","kind":"scalar","type":"String"},{"name":"employeeId","kind":"scalar","type":"String"},{"name":"designation","kind":"scalar","type":"String"},{"name":"checkIn","kind":"scalar","type":"DateTime"},{"name":"checkOut","kind":"scalar","type":"DateTime"},{"name":"createdAt","kind":"scalar","type":"DateTime"},{"name":"updatedAt","kind":"scalar","type":"DateTime"}],"dbName":null},"Blog":{"fields":[{"name":"id","kind":"scalar","type":"String"},{"name":"title","kind":"scalar","type":"String"},{"name":"description","kind":"scalar","type":"String"},{"name":"imageUrl","kind":"scalar","type":"String"},{"name":"createdAt","kind":"scalar","type":"DateTime"},{"name":"updatedAt","kind":"scalar","type":"DateTime"}],"dbName":null},"Course":{"fields":[{"name":"id","kind":"scalar","type":"String"},{"name":"imageUrl","kind":"scalar","type":"String"},{"name":"title","kind":"scalar","type":"String"},{"name":"category","kind":"scalar","type":"String"},{"name":"instructor","kind":"scalar","type":"String"},{"name":"duration","kind":"scalar","type":"String"},{"name":"price","kind":"scalar","type":"Float"},{"name":"status","kind":"enum","type":"CourseStatus"},{"name":"description","kind":"scalar","type":"String"},{"name":"createdAt","kind":"scalar","type":"DateTime"},{"name":"updatedAt","kind":"scalar","type":"DateTime"}],"dbName":null},"Hero":{"fields":[{"name":"id","kind":"scalar","type":"String"},{"name":"title","kind":"scalar","type":"String"},{"name":"description","kind":"scalar","type":"String"},{"name":"imageUrl","kind":"scalar","type":"String"},{"name":"createdAt","kind":"scalar","type":"DateTime"},{"name":"updatedAt","kind":"scalar","type":"DateTime"}],"dbName":null},"Lead":{"fields":[{"name":"id","kind":"scalar","type":"String"},{"name":"name","kind":"scalar","type":"String"},{"name":"email","kind":"scalar","type":"String"},{"name":"phone","kind":"scalar","type":"String"},{"name":"from","kind":"scalar","type":"String"},{"name":"company","kind":"scalar","type":"String"},{"name":"date","kind":"scalar","type":"DateTime"},{"name":"createdAt","kind":"scalar","type":"DateTime"},{"name":"updatedAt","kind":"scalar","type":"DateTime"}],"dbName":null},"Portfolio":{"fields":[{"name":"id","kind":"scalar","type":"String"},{"name":"title","kind":"scalar","type":"String"},{"name":"category","kind":"scalar","type":"String"},{"name":"description","kind":"scalar","type":"String"},{"name":"imageUrl","kind":"scalar","type":"String"},{"name":"videoUrl","kind":"scalar","type":"String"},{"name":"createdAt","kind":"scalar","type":"DateTime"},{"name":"updatedAt","kind":"scalar","type":"DateTime"}],"dbName":null},"User":{"fields":[{"name":"id","kind":"scalar","type":"String"},{"name":"employeeId","kind":"scalar","type":"String"},{"name":"name","kind":"scalar","type":"String"},{"name":"email","kind":"scalar","type":"String"},{"name":"password","kind":"scalar","type":"String"},{"name":"phone","kind":"scalar","type":"String"},{"name":"photoUrl","kind":"scalar","type":"String"},{"name":"role","kind":"enum","type":"Role"},{"name":"designation","kind":"enum","type":"Designation"},{"name":"skills","kind":"scalar","type":"String"},{"name":"experience","kind":"scalar","type":"Int"},{"name":"department","kind":"scalar","type":"String"},{"name":"status","kind":"enum","type":"STATUS"},{"name":"createdAt","kind":"scalar","type":"DateTime"},{"name":"updatedAt","kind":"scalar","type":"DateTime"},{"name":"lastLogin","kind":"scalar","type":"DateTime"}],"dbName":null}},"enums":{},"types":{}}');
config.parameterizationSchema = {
  strings: JSON.parse('["where","Attendance.findUnique","Attendance.findUniqueOrThrow","orderBy","cursor","Attendance.findFirst","Attendance.findFirstOrThrow","Attendance.findMany","data","Attendance.createOne","Attendance.createMany","Attendance.createManyAndReturn","Attendance.updateOne","Attendance.updateMany","Attendance.updateManyAndReturn","create","update","Attendance.upsertOne","Attendance.deleteOne","Attendance.deleteMany","having","_count","_min","_max","Attendance.groupBy","Attendance.aggregate","Blog.findUnique","Blog.findUniqueOrThrow","Blog.findFirst","Blog.findFirstOrThrow","Blog.findMany","Blog.createOne","Blog.createMany","Blog.createManyAndReturn","Blog.updateOne","Blog.updateMany","Blog.updateManyAndReturn","Blog.upsertOne","Blog.deleteOne","Blog.deleteMany","Blog.groupBy","Blog.aggregate","Course.findUnique","Course.findUniqueOrThrow","Course.findFirst","Course.findFirstOrThrow","Course.findMany","Course.createOne","Course.createMany","Course.createManyAndReturn","Course.updateOne","Course.updateMany","Course.updateManyAndReturn","Course.upsertOne","Course.deleteOne","Course.deleteMany","_avg","_sum","Course.groupBy","Course.aggregate","Hero.findUnique","Hero.findUniqueOrThrow","Hero.findFirst","Hero.findFirstOrThrow","Hero.findMany","Hero.createOne","Hero.createMany","Hero.createManyAndReturn","Hero.updateOne","Hero.updateMany","Hero.updateManyAndReturn","Hero.upsertOne","Hero.deleteOne","Hero.deleteMany","Hero.groupBy","Hero.aggregate","Lead.findUnique","Lead.findUniqueOrThrow","Lead.findFirst","Lead.findFirstOrThrow","Lead.findMany","Lead.createOne","Lead.createMany","Lead.createManyAndReturn","Lead.updateOne","Lead.updateMany","Lead.updateManyAndReturn","Lead.upsertOne","Lead.deleteOne","Lead.deleteMany","Lead.groupBy","Lead.aggregate","Portfolio.findUnique","Portfolio.findUniqueOrThrow","Portfolio.findFirst","Portfolio.findFirstOrThrow","Portfolio.findMany","Portfolio.createOne","Portfolio.createMany","Portfolio.createManyAndReturn","Portfolio.updateOne","Portfolio.updateMany","Portfolio.updateManyAndReturn","Portfolio.upsertOne","Portfolio.deleteOne","Portfolio.deleteMany","Portfolio.groupBy","Portfolio.aggregate","User.findUnique","User.findUniqueOrThrow","User.findFirst","User.findFirstOrThrow","User.findMany","User.createOne","User.createMany","User.createManyAndReturn","User.updateOne","User.updateMany","User.updateManyAndReturn","User.upsertOne","User.deleteOne","User.deleteMany","User.groupBy","User.aggregate","AND","OR","NOT","id","employeeId","name","email","password","phone","photoUrl","Role","role","Designation","designation","skills","experience","department","STATUS","status","createdAt","updatedAt","lastLogin","equals","in","notIn","lt","lte","gt","gte","not","contains","startsWith","endsWith","title","category","description","imageUrl","videoUrl","from","company","date","instructor","duration","price","CourseStatus","employeeName","checkIn","checkOut","set","increment","decrement","multiply","divide"]'),
  graph: "iwI9cAt8AADnAQAwfQAABAAQfgAA5wEAMH8BAAAAAYABAQDMAQAhiQEBAMwBACGPAUAA0gEAIZABQADSAQAhqQEBAMwBACGqAUAA0gEAIasBQADTAQAhAQAAAAEAIAEAAAABACALfAAA5wEAMH0AAAQAEH4AAOcBADB_AQDMAQAhgAEBAMwBACGJAQEAzAEAIY8BQADSAQAhkAFAANIBACGpAQEAzAEAIaoBQADSAQAhqwFAANMBACEBqwEAAOgBACADAAAABAAgAwAABQAwBAAAAQAgAwAAAAQAIAMAAAUAMAQAAAEAIAMAAAAEACADAAAFADAEAAABACAIfwEAAAABgAEBAAAAAYkBAQAAAAGPAUAAAAABkAFAAAAAAakBAQAAAAGqAUAAAAABqwFAAAAAAQEIAAAJACAIfwEAAAABgAEBAAAAAYkBAQAAAAGPAUAAAAABkAFAAAAAAakBAQAAAAGqAUAAAAABqwFAAAAAAQEIAAALADABCAAACwAwCH8BAO4BACGAAQEA7gEAIYkBAQDuAQAhjwFAAPQBACGQAUAA9AEAIakBAQDuAQAhqgFAAPQBACGrAUAA9QEAIQIAAAABACAIAAAOACAIfwEA7gEAIYABAQDuAQAhiQEBAO4BACGPAUAA9AEAIZABQAD0AQAhqQEBAO4BACGqAUAA9AEAIasBQAD1AQAhAgAAAAQAIAgAABAAIAIAAAAEACAIAAAQACADAAAAAQAgDwAACQAgEAAADgAgAQAAAAEAIAEAAAAEACAEFQAAiQIAIBYAAIsCACAXAACKAgAgqwEAAOgBACALfAAA5gEAMH0AABcAEH4AAOYBADB_AQCxAQAhgAEBALEBACGJAQEAsQEAIY8BQAC3AQAhkAFAALcBACGpAQEAsQEAIaoBQAC3AQAhqwFAALgBACEDAAAABAAgAwAAFgAwFAAAFwAgAwAAAAQAIAMAAAUAMAQAAAEAIAl8AADlAQAwfQAAHQAQfgAA5QEAMH8BAAAAAY8BQADSAQAhkAFAANIBACGdAQEAzAEAIZ8BAQDMAQAhoAEBAM0BACEBAAAAGgAgAQAAABoAIAl8AADlAQAwfQAAHQAQfgAA5QEAMH8BAMwBACGPAUAA0gEAIZABQADSAQAhnQEBAMwBACGfAQEAzAEAIaABAQDNAQAhAaABAADoAQAgAwAAAB0AIAMAAB4AMAQAABoAIAMAAAAdACADAAAeADAEAAAaACADAAAAHQAgAwAAHgAwBAAAGgAgBn8BAAAAAY8BQAAAAAGQAUAAAAABnQEBAAAAAZ8BAQAAAAGgAQEAAAABAQgAACIAIAZ_AQAAAAGPAUAAAAABkAFAAAAAAZ0BAQAAAAGfAQEAAAABoAEBAAAAAQEIAAAkADABCAAAJAAwBn8BAO4BACGPAUAA9AEAIZABQAD0AQAhnQEBAO4BACGfAQEA7gEAIaABAQDvAQAhAgAAABoAIAgAACcAIAZ_AQDuAQAhjwFAAPQBACGQAUAA9AEAIZ0BAQDuAQAhnwEBAO4BACGgAQEA7wEAIQIAAAAdACAIAAApACACAAAAHQAgCAAAKQAgAwAAABoAIA8AACIAIBAAACcAIAEAAAAaACABAAAAHQAgBBUAAIYCACAWAACIAgAgFwAAhwIAIKABAADoAQAgCXwAAOQBADB9AAAwABB-AADkAQAwfwEAsQEAIY8BQAC3AQAhkAFAALcBACGdAQEAsQEAIZ8BAQCxAQAhoAEBALIBACEDAAAAHQAgAwAALwAwFAAAMAAgAwAAAB0AIAMAAB4AMAQAABoAIA58AADhAQAwfQAANgAQfgAA4QEAMH8BAAAAAY4BAADjAakBIo8BQADSAQAhkAFAANIBACGdAQEAzAEAIZ4BAQDMAQAhnwEBAMwBACGgAQEAzAEAIaUBAQDMAQAhpgEBAMwBACGnAQgA4gEAIQEAAAAzACABAAAAMwAgDnwAAOEBADB9AAA2ABB-AADhAQAwfwEAzAEAIY4BAADjAakBIo8BQADSAQAhkAFAANIBACGdAQEAzAEAIZ4BAQDMAQAhnwEBAMwBACGgAQEAzAEAIaUBAQDMAQAhpgEBAMwBACGnAQgA4gEAIQADAAAANgAgAwAANwAwBAAAMwAgAwAAADYAIAMAADcAMAQAADMAIAMAAAA2ACADAAA3ADAEAAAzACALfwEAAAABjgEAAACpAQKPAUAAAAABkAFAAAAAAZ0BAQAAAAGeAQEAAAABnwEBAAAAAaABAQAAAAGlAQEAAAABpgEBAAAAAacBCAAAAAEBCAAAOwAgC38BAAAAAY4BAAAAqQECjwFAAAAAAZABQAAAAAGdAQEAAAABngEBAAAAAZ8BAQAAAAGgAQEAAAABpQEBAAAAAaYBAQAAAAGnAQgAAAABAQgAAD0AMAEIAAA9ADALfwEA7gEAIY4BAACFAqkBIo8BQAD0AQAhkAFAAPQBACGdAQEA7gEAIZ4BAQDuAQAhnwEBAO4BACGgAQEA7gEAIaUBAQDuAQAhpgEBAO4BACGnAQgAhAIAIQIAAAAzACAIAABAACALfwEA7gEAIY4BAACFAqkBIo8BQAD0AQAhkAFAAPQBACGdAQEA7gEAIZ4BAQDuAQAhnwEBAO4BACGgAQEA7gEAIaUBAQDuAQAhpgEBAO4BACGnAQgAhAIAIQIAAAA2ACAIAABCACACAAAANgAgCAAAQgAgAwAAADMAIA8AADsAIBAAAEAAIAEAAAAzACABAAAANgAgBRUAAP8BACAWAACCAgAgFwAAgQIAIDgAAIACACA5AACDAgAgDnwAANoBADB9AABJABB-AADaAQAwfwEAsQEAIY4BAADcAakBIo8BQAC3AQAhkAFAALcBACGdAQEAsQEAIZ4BAQCxAQAhnwEBALEBACGgAQEAsQEAIaUBAQCxAQAhpgEBALEBACGnAQgA2wEAIQMAAAA2ACADAABIADAUAABJACADAAAANgAgAwAANwAwBAAAMwAgCXwAANkBADB9AABPABB-AADZAQAwfwEAAAABjwFAANIBACGQAUAA0gEAIZ0BAQDMAQAhnwEBAMwBACGgAQEAzAEAIQEAAABMACABAAAATAAgCXwAANkBADB9AABPABB-AADZAQAwfwEAzAEAIY8BQADSAQAhkAFAANIBACGdAQEAzAEAIZ8BAQDMAQAhoAEBAMwBACEAAwAAAE8AIAMAAFAAMAQAAEwAIAMAAABPACADAABQADAEAABMACADAAAATwAgAwAAUAAwBAAATAAgBn8BAAAAAY8BQAAAAAGQAUAAAAABnQEBAAAAAZ8BAQAAAAGgAQEAAAABAQgAAFQAIAZ_AQAAAAGPAUAAAAABkAFAAAAAAZ0BAQAAAAGfAQEAAAABoAEBAAAAAQEIAABWADABCAAAVgAwBn8BAO4BACGPAUAA9AEAIZABQAD0AQAhnQEBAO4BACGfAQEA7gEAIaABAQDuAQAhAgAAAEwAIAgAAFkAIAZ_AQDuAQAhjwFAAPQBACGQAUAA9AEAIZ0BAQDuAQAhnwEBAO4BACGgAQEA7gEAIQIAAABPACAIAABbACACAAAATwAgCAAAWwAgAwAAAEwAIA8AAFQAIBAAAFkAIAEAAABMACABAAAATwAgAxUAAPwBACAWAAD-AQAgFwAA_QEAIAl8AADYAQAwfQAAYgAQfgAA2AEAMH8BALEBACGPAUAAtwEAIZABQAC3AQAhnQEBALEBACGfAQEAsQEAIaABAQCxAQAhAwAAAE8AIAMAAGEAMBQAAGIAIAMAAABPACADAABQADAEAABMACAMfAAA1wEAMH0AAGgAEH4AANcBADB_AQAAAAGBAQEAzAEAIYIBAQDMAQAhhAEBAM0BACGPAUAA0gEAIZABQADSAQAhogEBAMwBACGjAQEAzQEAIaQBQADSAQAhAQAAAGUAIAEAAABlACAMfAAA1wEAMH0AAGgAEH4AANcBADB_AQDMAQAhgQEBAMwBACGCAQEAzAEAIYQBAQDNAQAhjwFAANIBACGQAUAA0gEAIaIBAQDMAQAhowEBAM0BACGkAUAA0gEAIQKEAQAA6AEAIKMBAADoAQAgAwAAAGgAIAMAAGkAMAQAAGUAIAMAAABoACADAABpADAEAABlACADAAAAaAAgAwAAaQAwBAAAZQAgCX8BAAAAAYEBAQAAAAGCAQEAAAABhAEBAAAAAY8BQAAAAAGQAUAAAAABogEBAAAAAaMBAQAAAAGkAUAAAAABAQgAAG0AIAl_AQAAAAGBAQEAAAABggEBAAAAAYQBAQAAAAGPAUAAAAABkAFAAAAAAaIBAQAAAAGjAQEAAAABpAFAAAAAAQEIAABvADABCAAAbwAwCX8BAO4BACGBAQEA7gEAIYIBAQDuAQAhhAEBAO8BACGPAUAA9AEAIZABQAD0AQAhogEBAO4BACGjAQEA7wEAIaQBQAD0AQAhAgAAAGUAIAgAAHIAIAl_AQDuAQAhgQEBAO4BACGCAQEA7gEAIYQBAQDvAQAhjwFAAPQBACGQAUAA9AEAIaIBAQDuAQAhowEBAO8BACGkAUAA9AEAIQIAAABoACAIAAB0ACACAAAAaAAgCAAAdAAgAwAAAGUAIA8AAG0AIBAAAHIAIAEAAABlACABAAAAaAAgBRUAAPkBACAWAAD7AQAgFwAA-gEAIIQBAADoAQAgowEAAOgBACAMfAAA1gEAMH0AAHsAEH4AANYBADB_AQCxAQAhgQEBALEBACGCAQEAsQEAIYQBAQCyAQAhjwFAALcBACGQAUAAtwEAIaIBAQCxAQAhowEBALIBACGkAUAAtwEAIQMAAABoACADAAB6ADAUAAB7ACADAAAAaAAgAwAAaQAwBAAAZQAgC3wAANUBADB9AACBAQAQfgAA1QEAMH8BAAAAAY8BQADSAQAhkAFAANIBACGdAQEAzAEAIZ4BAQDMAQAhnwEBAMwBACGgAQEAzQEAIaEBAQDNAQAhAQAAAH4AIAEAAAB-ACALfAAA1QEAMH0AAIEBABB-AADVAQAwfwEAzAEAIY8BQADSAQAhkAFAANIBACGdAQEAzAEAIZ4BAQDMAQAhnwEBAMwBACGgAQEAzQEAIaEBAQDNAQAhAqABAADoAQAgoQEAAOgBACADAAAAgQEAIAMAAIIBADAEAAB-ACADAAAAgQEAIAMAAIIBADAEAAB-ACADAAAAgQEAIAMAAIIBADAEAAB-ACAIfwEAAAABjwFAAAAAAZABQAAAAAGdAQEAAAABngEBAAAAAZ8BAQAAAAGgAQEAAAABoQEBAAAAAQEIAACGAQAgCH8BAAAAAY8BQAAAAAGQAUAAAAABnQEBAAAAAZ4BAQAAAAGfAQEAAAABoAEBAAAAAaEBAQAAAAEBCAAAiAEAMAEIAACIAQAwCH8BAO4BACGPAUAA9AEAIZABQAD0AQAhnQEBAO4BACGeAQEA7gEAIZ8BAQDuAQAhoAEBAO8BACGhAQEA7wEAIQIAAAB-ACAIAACLAQAgCH8BAO4BACGPAUAA9AEAIZABQAD0AQAhnQEBAO4BACGeAQEA7gEAIZ8BAQDuAQAhoAEBAO8BACGhAQEA7wEAIQIAAACBAQAgCAAAjQEAIAIAAACBAQAgCAAAjQEAIAMAAAB-ACAPAACGAQAgEAAAiwEAIAEAAAB-ACABAAAAgQEAIAUVAAD2AQAgFgAA-AEAIBcAAPcBACCgAQAA6AEAIKEBAADoAQAgC3wAANQBADB9AACUAQAQfgAA1AEAMH8BALEBACGPAUAAtwEAIZABQAC3AQAhnQEBALEBACGeAQEAsQEAIZ8BAQCxAQAhoAEBALIBACGhAQEAsgEAIQMAAACBAQAgAwAAkwEAMBQAAJQBACADAAAAgQEAIAMAAIIBADAEAAB-ACATfAAAywEAMH0AAJoBABB-AADLAQAwfwEAAAABgAEBAAAAAYEBAQDMAQAhggEBAAAAAYMBAQDMAQAhhAEBAM0BACGFAQEAzQEAIYcBAADOAYcBIokBAADPAYkBI4oBAQDNAQAhiwECANABACGMAQEAzQEAIY4BAADRAY4BIo8BQADSAQAhkAFAANIBACGRAUAA0wEAIQEAAACXAQAgAQAAAJcBACATfAAAywEAMH0AAJoBABB-AADLAQAwfwEAzAEAIYABAQDMAQAhgQEBAMwBACGCAQEAzAEAIYMBAQDMAQAhhAEBAM0BACGFAQEAzQEAIYcBAADOAYcBIokBAADPAYkBI4oBAQDNAQAhiwECANABACGMAQEAzQEAIY4BAADRAY4BIo8BQADSAQAhkAFAANIBACGRAUAA0wEAIQeEAQAA6AEAIIUBAADoAQAgiQEAAOgBACCKAQAA6AEAIIsBAADoAQAgjAEAAOgBACCRAQAA6AEAIAMAAACaAQAgAwAAmwEAMAQAAJcBACADAAAAmgEAIAMAAJsBADAEAACXAQAgAwAAAJoBACADAACbAQAwBAAAlwEAIBB_AQAAAAGAAQEAAAABgQEBAAAAAYIBAQAAAAGDAQEAAAABhAEBAAAAAYUBAQAAAAGHAQAAAIcBAokBAAAAiQEDigEBAAAAAYsBAgAAAAGMAQEAAAABjgEAAACOAQKPAUAAAAABkAFAAAAAAZEBQAAAAAEBCAAAnwEAIBB_AQAAAAGAAQEAAAABgQEBAAAAAYIBAQAAAAGDAQEAAAABhAEBAAAAAYUBAQAAAAGHAQAAAIcBAokBAAAAiQEDigEBAAAAAYsBAgAAAAGMAQEAAAABjgEAAACOAQKPAUAAAAABkAFAAAAAAZEBQAAAAAEBCAAAoQEAMAEIAAChAQAwEH8BAO4BACGAAQEA7gEAIYEBAQDuAQAhggEBAO4BACGDAQEA7gEAIYQBAQDvAQAhhQEBAO8BACGHAQAA8AGHASKJAQAA8QGJASOKAQEA7wEAIYsBAgDyAQAhjAEBAO8BACGOAQAA8wGOASKPAUAA9AEAIZABQAD0AQAhkQFAAPUBACECAAAAlwEAIAgAAKQBACAQfwEA7gEAIYABAQDuAQAhgQEBAO4BACGCAQEA7gEAIYMBAQDuAQAhhAEBAO8BACGFAQEA7wEAIYcBAADwAYcBIokBAADxAYkBI4oBAQDvAQAhiwECAPIBACGMAQEA7wEAIY4BAADzAY4BIo8BQAD0AQAhkAFAAPQBACGRAUAA9QEAIQIAAACaAQAgCAAApgEAIAIAAACaAQAgCAAApgEAIAMAAACXAQAgDwAAnwEAIBAAAKQBACABAAAAlwEAIAEAAACaAQAgDBUAAOkBACAWAADsAQAgFwAA6wEAIDgAAOoBACA5AADtAQAghAEAAOgBACCFAQAA6AEAIIkBAADoAQAgigEAAOgBACCLAQAA6AEAIIwBAADoAQAgkQEAAOgBACATfAAAsAEAMH0AAK0BABB-AACwAQAwfwEAsQEAIYABAQCxAQAhgQEBALEBACGCAQEAsQEAIYMBAQCxAQAhhAEBALIBACGFAQEAsgEAIYcBAACzAYcBIokBAAC0AYkBI4oBAQCyAQAhiwECALUBACGMAQEAsgEAIY4BAAC2AY4BIo8BQAC3AQAhkAFAALcBACGRAUAAuAEAIQMAAACaAQAgAwAArAEAMBQAAK0BACADAAAAmgEAIAMAAJsBADAEAACXAQAgE3wAALABADB9AACtAQAQfgAAsAEAMH8BALEBACGAAQEAsQEAIYEBAQCxAQAhggEBALEBACGDAQEAsQEAIYQBAQCyAQAhhQEBALIBACGHAQAAswGHASKJAQAAtAGJASOKAQEAsgEAIYsBAgC1AQAhjAEBALIBACGOAQAAtgGOASKPAUAAtwEAIZABQAC3AQAhkQFAALgBACEOFQAAvQEAIBYAAMoBACAXAADKAQAgkgEBAAAAAZMBAQAAAASUAQEAAAAElQEBAAAAAZYBAQAAAAGXAQEAAAABmAEBAAAAAZkBAQDJAQAhmgEBAAAAAZsBAQAAAAGcAQEAAAABDhUAALoBACAWAADIAQAgFwAAyAEAIJIBAQAAAAGTAQEAAAAFlAEBAAAABZUBAQAAAAGWAQEAAAABlwEBAAAAAZgBAQAAAAGZAQEAxwEAIZoBAQAAAAGbAQEAAAABnAEBAAAAAQcVAAC9AQAgFgAAxgEAIBcAAMYBACCSAQAAAIcBApMBAAAAhwEIlAEAAACHAQiZAQAAxQGHASIHFQAAugEAIBYAAMQBACAXAADEAQAgkgEAAACJAQOTAQAAAIkBCZQBAAAAiQEJmQEAAMMBiQEjDRUAALoBACAWAAC6AQAgFwAAugEAIDgAAMIBACA5AAC6AQAgkgECAAAAAZMBAgAAAAWUAQIAAAAFlQECAAAAAZYBAgAAAAGXAQIAAAABmAECAAAAAZkBAgDBAQAhBxUAAL0BACAWAADAAQAgFwAAwAEAIJIBAAAAjgECkwEAAACOAQiUAQAAAI4BCJkBAAC_AY4BIgsVAAC9AQAgFgAAvgEAIBcAAL4BACCSAUAAAAABkwFAAAAABJQBQAAAAASVAUAAAAABlgFAAAAAAZcBQAAAAAGYAUAAAAABmQFAALwBACELFQAAugEAIBYAALsBACAXAAC7AQAgkgFAAAAAAZMBQAAAAAWUAUAAAAAFlQFAAAAAAZYBQAAAAAGXAUAAAAABmAFAAAAAAZkBQAC5AQAhCxUAALoBACAWAAC7AQAgFwAAuwEAIJIBQAAAAAGTAUAAAAAFlAFAAAAABZUBQAAAAAGWAUAAAAABlwFAAAAAAZgBQAAAAAGZAUAAuQEAIQiSAQIAAAABkwECAAAABZQBAgAAAAWVAQIAAAABlgECAAAAAZcBAgAAAAGYAQIAAAABmQECALoBACEIkgFAAAAAAZMBQAAAAAWUAUAAAAAFlQFAAAAAAZYBQAAAAAGXAUAAAAABmAFAAAAAAZkBQAC7AQAhCxUAAL0BACAWAAC-AQAgFwAAvgEAIJIBQAAAAAGTAUAAAAAElAFAAAAABJUBQAAAAAGWAUAAAAABlwFAAAAAAZgBQAAAAAGZAUAAvAEAIQiSAQIAAAABkwECAAAABJQBAgAAAASVAQIAAAABlgECAAAAAZcBAgAAAAGYAQIAAAABmQECAL0BACEIkgFAAAAAAZMBQAAAAASUAUAAAAAElQFAAAAAAZYBQAAAAAGXAUAAAAABmAFAAAAAAZkBQAC-AQAhBxUAAL0BACAWAADAAQAgFwAAwAEAIJIBAAAAjgECkwEAAACOAQiUAQAAAI4BCJkBAAC_AY4BIgSSAQAAAI4BApMBAAAAjgEIlAEAAACOAQiZAQAAwAGOASINFQAAugEAIBYAALoBACAXAAC6AQAgOAAAwgEAIDkAALoBACCSAQIAAAABkwECAAAABZQBAgAAAAWVAQIAAAABlgECAAAAAZcBAgAAAAGYAQIAAAABmQECAMEBACEIkgEIAAAAAZMBCAAAAAWUAQgAAAAFlQEIAAAAAZYBCAAAAAGXAQgAAAABmAEIAAAAAZkBCADCAQAhBxUAALoBACAWAADEAQAgFwAAxAEAIJIBAAAAiQEDkwEAAACJAQmUAQAAAIkBCZkBAADDAYkBIwSSAQAAAIkBA5MBAAAAiQEJlAEAAACJAQmZAQAAxAGJASMHFQAAvQEAIBYAAMYBACAXAADGAQAgkgEAAACHAQKTAQAAAIcBCJQBAAAAhwEImQEAAMUBhwEiBJIBAAAAhwECkwEAAACHAQiUAQAAAIcBCJkBAADGAYcBIg4VAAC6AQAgFgAAyAEAIBcAAMgBACCSAQEAAAABkwEBAAAABZQBAQAAAAWVAQEAAAABlgEBAAAAAZcBAQAAAAGYAQEAAAABmQEBAMcBACGaAQEAAAABmwEBAAAAAZwBAQAAAAELkgEBAAAAAZMBAQAAAAWUAQEAAAAFlQEBAAAAAZYBAQAAAAGXAQEAAAABmAEBAAAAAZkBAQDIAQAhmgEBAAAAAZsBAQAAAAGcAQEAAAABDhUAAL0BACAWAADKAQAgFwAAygEAIJIBAQAAAAGTAQEAAAAElAEBAAAABJUBAQAAAAGWAQEAAAABlwEBAAAAAZgBAQAAAAGZAQEAyQEAIZoBAQAAAAGbAQEAAAABnAEBAAAAAQuSAQEAAAABkwEBAAAABJQBAQAAAASVAQEAAAABlgEBAAAAAZcBAQAAAAGYAQEAAAABmQEBAMoBACGaAQEAAAABmwEBAAAAAZwBAQAAAAETfAAAywEAMH0AAJoBABB-AADLAQAwfwEAzAEAIYABAQDMAQAhgQEBAMwBACGCAQEAzAEAIYMBAQDMAQAhhAEBAM0BACGFAQEAzQEAIYcBAADOAYcBIokBAADPAYkBI4oBAQDNAQAhiwECANABACGMAQEAzQEAIY4BAADRAY4BIo8BQADSAQAhkAFAANIBACGRAUAA0wEAIQuSAQEAAAABkwEBAAAABJQBAQAAAASVAQEAAAABlgEBAAAAAZcBAQAAAAGYAQEAAAABmQEBAMoBACGaAQEAAAABmwEBAAAAAZwBAQAAAAELkgEBAAAAAZMBAQAAAAWUAQEAAAAFlQEBAAAAAZYBAQAAAAGXAQEAAAABmAEBAAAAAZkBAQDIAQAhmgEBAAAAAZsBAQAAAAGcAQEAAAABBJIBAAAAhwECkwEAAACHAQiUAQAAAIcBCJkBAADGAYcBIgSSAQAAAIkBA5MBAAAAiQEJlAEAAACJAQmZAQAAxAGJASMIkgECAAAAAZMBAgAAAAWUAQIAAAAFlQECAAAAAZYBAgAAAAGXAQIAAAABmAECAAAAAZkBAgC6AQAhBJIBAAAAjgECkwEAAACOAQiUAQAAAI4BCJkBAADAAY4BIgiSAUAAAAABkwFAAAAABJQBQAAAAASVAUAAAAABlgFAAAAAAZcBQAAAAAGYAUAAAAABmQFAAL4BACEIkgFAAAAAAZMBQAAAAAWUAUAAAAAFlQFAAAAAAZYBQAAAAAGXAUAAAAABmAFAAAAAAZkBQAC7AQAhC3wAANQBADB9AACUAQAQfgAA1AEAMH8BALEBACGPAUAAtwEAIZABQAC3AQAhnQEBALEBACGeAQEAsQEAIZ8BAQCxAQAhoAEBALIBACGhAQEAsgEAIQt8AADVAQAwfQAAgQEAEH4AANUBADB_AQDMAQAhjwFAANIBACGQAUAA0gEAIZ0BAQDMAQAhngEBAMwBACGfAQEAzAEAIaABAQDNAQAhoQEBAM0BACEMfAAA1gEAMH0AAHsAEH4AANYBADB_AQCxAQAhgQEBALEBACGCAQEAsQEAIYQBAQCyAQAhjwFAALcBACGQAUAAtwEAIaIBAQCxAQAhowEBALIBACGkAUAAtwEAIQx8AADXAQAwfQAAaAAQfgAA1wEAMH8BAMwBACGBAQEAzAEAIYIBAQDMAQAhhAEBAM0BACGPAUAA0gEAIZABQADSAQAhogEBAMwBACGjAQEAzQEAIaQBQADSAQAhCXwAANgBADB9AABiABB-AADYAQAwfwEAsQEAIY8BQAC3AQAhkAFAALcBACGdAQEAsQEAIZ8BAQCxAQAhoAEBALEBACEJfAAA2QEAMH0AAE8AEH4AANkBADB_AQDMAQAhjwFAANIBACGQAUAA0gEAIZ0BAQDMAQAhnwEBAMwBACGgAQEAzAEAIQ58AADaAQAwfQAASQAQfgAA2gEAMH8BALEBACGOAQAA3AGpASKPAUAAtwEAIZABQAC3AQAhnQEBALEBACGeAQEAsQEAIZ8BAQCxAQAhoAEBALEBACGlAQEAsQEAIaYBAQCxAQAhpwEIANsBACENFQAAvQEAIBYAAOABACAXAADgAQAgOAAA4AEAIDkAAOABACCSAQgAAAABkwEIAAAABJQBCAAAAASVAQgAAAABlgEIAAAAAZcBCAAAAAGYAQgAAAABmQEIAN8BACEHFQAAvQEAIBYAAN4BACAXAADeAQAgkgEAAACpAQKTAQAAAKkBCJQBAAAAqQEImQEAAN0BqQEiBxUAAL0BACAWAADeAQAgFwAA3gEAIJIBAAAAqQECkwEAAACpAQiUAQAAAKkBCJkBAADdAakBIgSSAQAAAKkBApMBAAAAqQEIlAEAAACpAQiZAQAA3gGpASINFQAAvQEAIBYAAOABACAXAADgAQAgOAAA4AEAIDkAAOABACCSAQgAAAABkwEIAAAABJQBCAAAAASVAQgAAAABlgEIAAAAAZcBCAAAAAGYAQgAAAABmQEIAN8BACEIkgEIAAAAAZMBCAAAAASUAQgAAAAElQEIAAAAAZYBCAAAAAGXAQgAAAABmAEIAAAAAZkBCADgAQAhDnwAAOEBADB9AAA2ABB-AADhAQAwfwEAzAEAIY4BAADjAakBIo8BQADSAQAhkAFAANIBACGdAQEAzAEAIZ4BAQDMAQAhnwEBAMwBACGgAQEAzAEAIaUBAQDMAQAhpgEBAMwBACGnAQgA4gEAIQiSAQgAAAABkwEIAAAABJQBCAAAAASVAQgAAAABlgEIAAAAAZcBCAAAAAGYAQgAAAABmQEIAOABACEEkgEAAACpAQKTAQAAAKkBCJQBAAAAqQEImQEAAN4BqQEiCXwAAOQBADB9AAAwABB-AADkAQAwfwEAsQEAIY8BQAC3AQAhkAFAALcBACGdAQEAsQEAIZ8BAQCxAQAhoAEBALIBACEJfAAA5QEAMH0AAB0AEH4AAOUBADB_AQDMAQAhjwFAANIBACGQAUAA0gEAIZ0BAQDMAQAhnwEBAMwBACGgAQEAzQEAIQt8AADmAQAwfQAAFwAQfgAA5gEAMH8BALEBACGAAQEAsQEAIYkBAQCxAQAhjwFAALcBACGQAUAAtwEAIakBAQCxAQAhqgFAALcBACGrAUAAuAEAIQt8AADnAQAwfQAABAAQfgAA5wEAMH8BAMwBACGAAQEAzAEAIYkBAQDMAQAhjwFAANIBACGQAUAA0gEAIakBAQDMAQAhqgFAANIBACGrAUAA0wEAIQAAAAAAAAGsAQEAAAABAawBAQAAAAEBrAEAAACHAQIBrAEAAACJAQMFrAECAAAAAa0BAgAAAAGuAQIAAAABrwECAAAAAbABAgAAAAEBrAEAAACOAQIBrAFAAAAAAQGsAUAAAAABAAAAAAAAAAAAAAAAAAAFrAEIAAAAAa0BCAAAAAGuAQgAAAABrwEIAAAAAbABCAAAAAEBrAEAAACpAQIAAAAAAAAAAAAAAxUABhYABxcACAAAAAMVAAYWAAcXAAgAAAADFQAOFgAPFwAQAAAAAxUADhYADxcAEAAAAAUVABYWABkXABo4ABc5ABgAAAAAAAUVABYWABkXABo4ABc5ABgAAAADFQAgFgAhFwAiAAAAAxUAIBYAIRcAIgAAAAMVACgWACkXACoAAAADFQAoFgApFwAqAAAAAxUAMBYAMRcAMgAAAAMVADAWADEXADIAAAAFFQA4FgA7FwA8OAA5OQA6AAAAAAAFFQA4FgA7FwA8OAA5OQA6AQIBAgMBBQYBBgcBBwgBCQoBCgwCCw0DDA8BDRECDhIEERMBEhQBExUCGBgFGRkJGhsKGxwKHB8KHSAKHiEKHyMKICUCISYLIigKIyoCJCsMJSwKJi0KJy4CKDENKTIRKjQSKzUSLDgSLTkSLjoSLzwSMD4CMT8TMkESM0MCNEQUNUUSNkYSN0cCOkoVO0sbPE0cPU4cPlEcP1IcQFMcQVUcQlcCQ1gdRFocRVwCRl0eR14cSF8cSWACSmMfS2QjTGYkTWckTmokT2skUGwkUW4kUnACU3ElVHMkVXUCVnYmV3ckWHgkWXkCWnwnW30rXH8sXYABLF6DASxfhAEsYIUBLGGHASxiiQECY4oBLWSMASxljgECZo8BLmeQASxokQEsaZIBAmqVAS9rlgEzbJgBNG2ZATRunAE0b50BNHCeATRxoAE0cqIBAnOjATV0pQE0dacBAnaoATZ3qQE0eKoBNHmrAQJ6rgE3e68BPQ"
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
      employeeId: user.employeeId,
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
var getSingleUser = async (id) => {
  return await prisma.user.findUnique({
    where: { id }
  });
};
var updateUser = async (id, payload) => {
  if (payload.password) {
    payload.password = await bcrypt.hash(payload.password, 10);
  }
  return await prisma.user.update({
    where: { id },
    data: payload,
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
  loginUser,
  getSingleUser,
  updateUser
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
var getSingleUser2 = catchAsync(async (req, res) => {
  const { id } = req.params;
  const result = await UseService.getSingleUser(id);
  sendResponse(res, {
    httpStatusCode: 200,
    success: true,
    message: "user fetched successfully",
    data: result
  });
});
var updateUser2 = catchAsync(async (req, res) => {
  const { id } = req.params;
  const payload = req.body;
  const result = await UseService.updateUser(id, payload);
  sendResponse(res, {
    httpStatusCode: 200,
    success: true,
    message: "user updated successfully",
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
  loginUser: loginUser2,
  getSingleUser: getSingleUser2,
  updateUser: updateUser2
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
router.post("/", UserController.registerUser);
router.post("/login", UserController.loginUser);
router.get("/", UserController.getAllUsers);
router.get(
  "/:id",
  auth(Role.ADMIN, Role.MANAGER),
  UserController.getSingleUser
);
router.put(
  "/:id",
  auth(Role.EMPLOY, Role.ADMIN, Role.MANAGER),
  UserController.updateUser
);
router.delete("/:id", auth(Role.ADMIN), UserController.deleteUser);
var UserRoute = router;

// src/app/modules/blog/blog.route.ts
import express from "express";

// src/app/modules/blog/blog.service.ts
var createBlog = async (payload) => {
  const result = await prisma.blog.create({
    data: payload
  });
  return result;
};
var getAllBlogs = async (query) => {
  const { page = 1, limit = 10, search } = query;
  const skip = (Number(page) - 1) * Number(limit);
  const whereCondition = search ? {
    title: {
      contains: search,
      mode: "insensitive"
    }
  } : {};
  const result = await prisma.blog.findMany({
    where: whereCondition,
    skip,
    take: Number(limit),
    orderBy: {
      createdAt: "desc"
    }
  });
  const total = await prisma.blog.count({
    where: whereCondition
  });
  return {
    meta: {
      page: Number(page),
      limit: Number(limit),
      total
    },
    data: result
  };
};
var getSingleBlog = async (id) => {
  return await prisma.blog.findUnique({
    where: { id }
  });
};
var updateBlog = async (id, payload) => {
  return await prisma.blog.update({
    where: { id },
    data: payload
  });
};
var deleteBlog = async (id) => {
  return await prisma.blog.delete({
    where: { id }
  });
};
var BlogService = {
  createBlog,
  getAllBlogs,
  getSingleBlog,
  updateBlog,
  deleteBlog
};

// src/app/modules/blog/blog.controller.ts
var createBlog2 = async (req, res) => {
  const result = await BlogService.createBlog(req.body);
  res.status(201).json({
    success: true,
    message: "Blog created successfully",
    data: result
  });
};
var getAllBlogs2 = async (req, res) => {
  const result = await BlogService.getAllBlogs(req.query);
  res.status(200).json({
    success: true,
    ...result
  });
};
var getSingleBlog2 = async (req, res) => {
  const { id } = req.params;
  const result = await BlogService.getSingleBlog(id);
  res.status(200).json({
    success: true,
    data: result
  });
};
var updateBlog2 = async (req, res) => {
  const { id } = req.params;
  const result = await BlogService.updateBlog(id, req.body);
  res.status(200).json({
    success: true,
    message: "Blog updated successfully",
    data: result
  });
};
var deleteBlog2 = async (req, res) => {
  const { id } = req.params;
  await BlogService.deleteBlog(id);
  res.status(200).json({
    success: true,
    message: "Blog deleted successfully"
  });
};
var BlogController = {
  createBlog: createBlog2,
  getAllBlogs: getAllBlogs2,
  getSingleBlog: getSingleBlog2,
  updateBlog: updateBlog2,
  deleteBlog: deleteBlog2
};

// src/app/modules/blog/blog.route.ts
var router2 = express.Router();
router2.get("/", BlogController.getAllBlogs);
router2.get("/:id", BlogController.getSingleBlog);
router2.post("/", auth(Role.ADMIN), BlogController.createBlog);
router2.patch("/:id", auth("ADMIN"), BlogController.updateBlog);
router2.delete("/:id", auth("ADMIN"), BlogController.deleteBlog);
var BlogRoutes = router2;

// src/app/modules/hero-managenment/hero.route.ts
import express2 from "express";

// src/app/modules/hero-managenment/hero.service.ts
var createHero = async (payload) => {
  return await prisma.hero.create({
    data: payload
  });
};
var getAllHero = async () => {
  return await prisma.hero.findMany({
    orderBy: {
      createdAt: "desc"
    }
  });
};
var getSingleHero = async (id) => {
  return await prisma.hero.findUnique({
    where: { id }
  });
};
var updateHero = async (id, payload) => {
  return await prisma.hero.update({
    where: { id },
    data: payload
  });
};
var deleteHero = async (id) => {
  return await prisma.hero.delete({
    where: { id }
  });
};
var HeroService = {
  createHero,
  getAllHero,
  getSingleHero,
  updateHero,
  deleteHero
};

// src/app/modules/hero-managenment/hero.controller.ts
var createHero2 = async (req, res) => {
  const result = await HeroService.createHero(req.body);
  res.status(201).json({
    success: true,
    message: "Hero content created successfully",
    data: result
  });
};
var getAllHero2 = async (req, res) => {
  const result = await HeroService.getAllHero();
  res.status(200).json({
    success: true,
    data: result
  });
};
var getSingleHero2 = async (req, res) => {
  const result = await HeroService.getSingleHero(req.params.id);
  res.status(200).json({
    success: true,
    data: result
  });
};
var updateHero2 = async (req, res) => {
  const result = await HeroService.updateHero(
    req.params.id,
    req.body
  );
  res.status(200).json({
    success: true,
    message: "Hero updated successfully",
    data: result
  });
};
var deleteHero2 = async (req, res) => {
  await HeroService.deleteHero(req.params.id);
  res.status(200).json({
    success: true,
    message: "Hero deleted successfully"
  });
};
var HeroController = {
  createHero: createHero2,
  getAllHero: getAllHero2,
  getSingleHero: getSingleHero2,
  updateHero: updateHero2,
  deleteHero: deleteHero2
};

// src/app/modules/hero-managenment/hero.route.ts
var router3 = express2.Router();
router3.get("/", HeroController.getAllHero);
router3.get("/:id", HeroController.getSingleHero);
router3.post("/", auth("ADMIN"), HeroController.createHero);
router3.patch("/:id", auth("ADMIN"), HeroController.updateHero);
router3.delete("/:id", auth("ADMIN"), HeroController.deleteHero);
var HeroRoutes = router3;

// src/app/modules/portfolio/portfolio.route.ts
import express3 from "express";

// src/app/modules/portfolio/portfolio.service.ts
var createPortfolio = async (payload) => {
  return await prisma.portfolio.create({
    data: payload
  });
};
var getAllPortfolio = async (query) => {
  const { page = 1, limit = 10, category } = query;
  const skip = (Number(page) - 1) * Number(limit);
  const whereCondition = category ? { category: { equals: category, mode: "insensitive" } } : {};
  const data = await prisma.portfolio.findMany({
    where: whereCondition,
    skip,
    take: Number(limit),
    orderBy: { createdAt: "desc" }
  });
  const total = await prisma.portfolio.count({
    where: whereCondition
  });
  return {
    meta: {
      page: Number(page),
      limit: Number(limit),
      total
    },
    data
  };
};
var getSinglePortfolio = async (id) => {
  return await prisma.portfolio.findUnique({
    where: { id }
  });
};
var updatePortfolio = async (id, payload) => {
  return await prisma.portfolio.update({
    where: { id },
    data: payload
  });
};
var deletePortfolio = async (id) => {
  return await prisma.portfolio.delete({
    where: { id }
  });
};
var PortfolioService = {
  createPortfolio,
  getAllPortfolio,
  getSinglePortfolio,
  updatePortfolio,
  deletePortfolio
};

// src/app/modules/portfolio/portfolio.controller.ts
var createPortfolio2 = async (req, res) => {
  const result = await PortfolioService.createPortfolio(req.body);
  res.status(201).json({
    success: true,
    message: "Portfolio created successfully",
    data: result
  });
};
var getAllPortfolio2 = async (req, res) => {
  const result = await PortfolioService.getAllPortfolio(req.query);
  res.status(200).json({
    success: true,
    ...result
  });
};
var getSinglePortfolio2 = async (req, res) => {
  const result = await PortfolioService.getSinglePortfolio(
    req.params.id
  );
  res.status(200).json({
    success: true,
    data: result
  });
};
var updatePortfolio2 = async (req, res) => {
  const result = await PortfolioService.updatePortfolio(
    req.params.id,
    req.body
  );
  res.status(200).json({
    success: true,
    message: "Portfolio updated successfully",
    data: result
  });
};
var deletePortfolio2 = async (req, res) => {
  await PortfolioService.deletePortfolio(req.params.id);
  res.status(200).json({
    success: true,
    message: "Portfolio deleted successfully"
  });
};
var PortfolioController = {
  createPortfolio: createPortfolio2,
  getAllPortfolio: getAllPortfolio2,
  getSinglePortfolio: getSinglePortfolio2,
  updatePortfolio: updatePortfolio2,
  deletePortfolio: deletePortfolio2
};

// src/app/modules/portfolio/portfolio.route.ts
var router4 = express3.Router();
router4.get("/", PortfolioController.getAllPortfolio);
router4.get("/:id", PortfolioController.getSinglePortfolio);
router4.post("/", auth("ADMIN"), PortfolioController.createPortfolio);
router4.patch("/:id", auth("ADMIN"), PortfolioController.updatePortfolio);
router4.delete("/:id", auth("ADMIN"), PortfolioController.deletePortfolio);
var PortfolioRoutes = router4;

// src/app/modules/lead/lead.route.ts
import express4 from "express";

// src/app/modules/lead/lead.service.ts
var createLead = async (payload) => {
  return await prisma.lead.create({
    data: payload
  });
};
var getAllLeads = async (query) => {
  const { page = 1, limit = 10 } = query;
  const skip = (Number(page) - 1) * Number(limit);
  const data = await prisma.lead.findMany({
    skip,
    take: Number(limit),
    orderBy: {
      createdAt: "desc"
    }
  });
  const total = await prisma.lead.count();
  return {
    meta: {
      page: Number(page),
      limit: Number(limit),
      total
    },
    data
  };
};
var getSingleLead = async (id) => {
  return await prisma.lead.findUnique({
    where: { id }
  });
};
var deleteLead = async (id) => {
  return await prisma.lead.delete({
    where: { id }
  });
};
var LeadService = {
  createLead,
  getAllLeads,
  getSingleLead,
  deleteLead
};

// src/app/modules/lead/lead.controller.ts
var createLead2 = async (req, res) => {
  const result = await LeadService.createLead({
    ...req.body,
    date: new Date(req.body.date)
  });
  res.status(201).json({
    success: true,
    message: "Lead submitted successfully",
    data: result
  });
};
var getAllLeads2 = async (req, res) => {
  const result = await LeadService.getAllLeads(req.query);
  res.status(200).json({
    success: true,
    ...result
  });
};
var getSingleLead2 = async (req, res) => {
  const result = await LeadService.getSingleLead(req.params.id);
  res.status(200).json({
    success: true,
    data: result
  });
};
var deleteLead2 = async (req, res) => {
  await LeadService.deleteLead(req.params.id);
  res.status(200).json({
    success: true,
    message: "Lead deleted successfully"
  });
};
var LeadController = {
  createLead: createLead2,
  getAllLeads: getAllLeads2,
  getSingleLead: getSingleLead2,
  deleteLead: deleteLead2
};

// src/app/modules/lead/lead.route.ts
var router5 = express4.Router();
router5.post("/", LeadController.createLead);
router5.get("/", auth("ADMIN"), LeadController.getAllLeads);
router5.get("/:id", auth("ADMIN"), LeadController.getSingleLead);
router5.delete("/:id", auth("ADMIN"), LeadController.deleteLead);
var LeadRoutes = router5;

// src/app/modules/course/course.route.ts
import express5 from "express";

// src/app/modules/course/course.service.ts
var createCourse = async (payload) => {
  return await prisma.course.create({
    data: payload
  });
};
var getAllCourses = async (query) => {
  const { page = 1, limit = 10, category, status: status3 } = query;
  const skip = (Number(page) - 1) * Number(limit);
  const whereCondition = {};
  if (category) {
    whereCondition.category = {
      equals: category,
      mode: "insensitive"
    };
  }
  if (status3) {
    whereCondition.status = status3;
  }
  const data = await prisma.course.findMany({
    where: whereCondition,
    skip,
    take: Number(limit),
    orderBy: {
      createdAt: "desc"
    }
  });
  const total = await prisma.course.count({
    where: whereCondition
  });
  return {
    meta: {
      page: Number(page),
      limit: Number(limit),
      total
    },
    data
  };
};
var getSingleCourse = async (id) => {
  return await prisma.course.findUnique({
    where: { id }
  });
};
var updateCourse = async (id, payload) => {
  return await prisma.course.update({
    where: { id },
    data: payload
  });
};
var deleteCourse = async (id) => {
  return await prisma.course.delete({
    where: { id }
  });
};
var CourseService = {
  createCourse,
  getAllCourses,
  getSingleCourse,
  updateCourse,
  deleteCourse
};

// src/app/modules/course/course.controller.ts
var createCourse2 = async (req, res) => {
  const result = await CourseService.createCourse(req.body);
  res.status(201).json({
    success: true,
    message: "Course created successfully",
    data: result
  });
};
var getAllCourses2 = async (req, res) => {
  const result = await CourseService.getAllCourses(req.query);
  res.status(200).json({
    success: true,
    ...result
  });
};
var getSingleCourse2 = async (req, res) => {
  const result = await CourseService.getSingleCourse(req.params.id);
  res.status(200).json({
    success: true,
    data: result
  });
};
var updateCourse2 = async (req, res) => {
  const result = await CourseService.updateCourse(
    req.params.id,
    req.body
  );
  res.status(200).json({
    success: true,
    message: "Course updated successfully",
    data: result
  });
};
var deleteCourse2 = async (req, res) => {
  await CourseService.deleteCourse(req.params.id);
  res.status(200).json({
    success: true,
    message: "Course deleted successfully"
  });
};
var CourseController = {
  createCourse: createCourse2,
  getAllCourses: getAllCourses2,
  getSingleCourse: getSingleCourse2,
  updateCourse: updateCourse2,
  deleteCourse: deleteCourse2
};

// src/app/modules/course/course.route.ts
var router6 = express5.Router();
router6.get("/", CourseController.getAllCourses);
router6.get("/:id", CourseController.getSingleCourse);
router6.post("/", auth("ADMIN"), CourseController.createCourse);
router6.patch("/:id", auth("ADMIN"), CourseController.updateCourse);
router6.delete("/:id", auth("ADMIN"), CourseController.deleteCourse);
var CourseRoutes = router6;

// src/app/modules/attendance/attendance.route.ts
import express6 from "express";

// src/app/modules/attendance/attendance.service.ts
var createAttendance = async (payload) => {
  return await prisma.attendance.create({
    data: payload
  });
};
var getAllAttendance = async (query) => {
  const { page = 1, limit = 10 } = query;
  const skip = (Number(page) - 1) * Number(limit);
  const data = await prisma.attendance.findMany({
    skip,
    take: Number(limit),
    orderBy: { createdAt: "desc" }
  });
  const total = await prisma.attendance.count();
  return {
    meta: { page: Number(page), limit: Number(limit), total },
    data
  };
};
var getSingleAttendance = async (id) => {
  return await prisma.attendance.findUnique({
    where: { id }
  });
};
var updateAttendance = async (id, payload) => {
  return await prisma.attendance.update({
    where: { id },
    data: payload
  });
};
var deleteAttendance = async (id) => {
  return await prisma.attendance.delete({
    where: { id }
  });
};
var getEmployeeAttendancePaginated = async (employeeId, page = 1, limit = 30) => {
  const skip = (page - 1) * limit;
  const records = await prisma.attendance.findMany({
    where: { employeeId },
    orderBy: { checkIn: "desc" },
    skip,
    take: limit
  });
  const total = await prisma.attendance.count({
    where: { employeeId }
  });
  return {
    total,
    page,
    limit,
    totalPages: Math.ceil(total / limit),
    records
  };
};
var AttendanceService = {
  createAttendance,
  getAllAttendance,
  getSingleAttendance,
  updateAttendance,
  deleteAttendance,
  getEmployeeAttendancePaginated
};

// src/app/modules/attendance/attendance.controller.ts
var createAttendance2 = async (req, res) => {
  try {
    const result = await AttendanceService.createAttendance({
      ...req.body,
      checkIn: new Date(req.body.checkIn),
      checkOut: req.body.checkOut ? new Date(req.body.checkOut) : void 0
    });
    res.status(201).json({
      success: true,
      message: "Attendance recorded successfully",
      data: result
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};
var getMyAttendance = async (req, res) => {
  try {
    const employeeId = req.user?.employeeId;
    console.log(employeeId);
    if (!employeeId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }
    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 30;
    const result = await AttendanceService.getEmployeeAttendancePaginated(
      employeeId,
      page,
      limit
    );
    res.status(200).json({ success: true, ...result });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};
var getAllAttendance2 = async (req, res) => {
  const result = await AttendanceService.getAllAttendance(req.query);
  res.status(200).json({ success: true, ...result });
};
var getSingleAttendance2 = async (req, res) => {
  const result = await AttendanceService.getSingleAttendance(
    req.params.id
  );
  res.status(200).json({ success: true, data: result });
};
var updateAttendance2 = async (req, res) => {
  try {
    const payload = {};
    if (req.body.checkOut) {
      payload.checkOut = new Date(req.body.checkOut);
    }
    const result = await AttendanceService.updateAttendance(
      req.params.id,
      payload
    );
    res.status(200).json({
      success: true,
      message: "Attendance updated",
      data: result
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};
var deleteAttendance2 = async (req, res) => {
  await AttendanceService.deleteAttendance(req.params.id);
  res.status(200).json({ success: true, message: "Attendance deleted" });
};
var AttendanceController = {
  createAttendance: createAttendance2,
  getMyAttendance,
  getAllAttendance: getAllAttendance2,
  getSingleAttendance: getSingleAttendance2,
  updateAttendance: updateAttendance2,
  deleteAttendance: deleteAttendance2
};

// src/app/modules/attendance/attendance.route.ts
var router7 = express6.Router();
router7.get(
  "/my",
  auth(Role.EMPLOY, Role.MANAGER, Role.ADMIN),
  AttendanceController.getMyAttendance
);
router7.post(
  "/",
  auth(Role.EMPLOY, Role.ADMIN, Role.MANAGER),
  AttendanceController.createAttendance
);
router7.get(
  "/",
  auth(Role.MANAGER, Role.ADMIN),
  AttendanceController.getAllAttendance
);
router7.get("/:id", auth(Role.ADMIN), AttendanceController.getSingleAttendance);
router7.patch(
  "/:id",
  auth(Role.EMPLOY, Role.MANAGER, Role.ADMIN),
  AttendanceController.updateAttendance
);
router7.delete("/:id", auth(Role.ADMIN), AttendanceController.deleteAttendance);
var AttendanceRoutes = router7;

// src/app/modules/stats/stats.route.ts
import express7 from "express";

// src/app/modules/stats/stats.service.ts
var getStats = async () => {
  const [users, blogs, leads, courses, portfolios] = await Promise.all([
    prisma.user.count(),
    prisma.blog.count(),
    prisma.lead.count(),
    prisma.course.count(),
    prisma.portfolio.count()
  ]);
  return {
    users,
    blogs,
    leads,
    courses,
    portfolios
  };
};
var StatsService = {
  getStats
};

// src/app/modules/stats/stats.controller.ts
var getStats2 = async (req, res) => {
  try {
    const result = await StatsService.getStats();
    res.status(200).json({
      success: true,
      message: "Stats fetched successfully",
      data: result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to fetch stats"
    });
  }
};
var StatsController = {
  getStats: getStats2
};

// src/app/modules/stats/stats.route.ts
var router8 = express7.Router();
router8.get("/", StatsController.getStats);
var StatsRoutes = router8;

// src/app/routes/index.ts
var router9 = Router2();
router9.use("/users", UserRoute);
router9.use("/blogs", BlogRoutes);
router9.use("/hero", HeroRoutes);
router9.use("/portfolio", PortfolioRoutes);
router9.use("/leads", LeadRoutes);
router9.use("/courses", CourseRoutes);
router9.use("/attendance", AttendanceRoutes);
router9.use("/stats", StatsRoutes);
var routes_default = router9;

// src/app.ts
var app = express8();
app.use(express8.urlencoded({ extended: true }));
app.use(express8.json());
app.use(
  cors({
    origin: ["http://localhost:3000", "https://deltadigivast.vercel.app"],
    credentials: true
  })
);
app.use("/api/v1", routes_default);
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
