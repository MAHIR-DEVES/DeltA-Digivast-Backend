import dotenv from 'dotenv';

dotenv.config();

interface EnvConfig {
  NODE_ENV: string;
  PORT: string;
  DATABASE_URL: string;
  JWT_SECRET: string;
}

const requiredEnvVars = ['NODE_ENV', 'PORT', 'DATABASE_URL', 'JWT_SECRET'];

requiredEnvVars.forEach(varName => {
  if (!process.env[varName]) {
    // throw new Error(
    //   `Environment variable ${varName} is required but not set in .env file.`,
    // );
    throw new Error(
      `Environment variable ${varName} is required but not set in .env file.`,
    );
  }
});

const loadEnvVariables = (): EnvConfig => {
  return {
    NODE_ENV: process.env.NODE_ENV as string,
    PORT: process.env.PORT as string,
    DATABASE_URL: process.env.DATABASE_URL as string,
    JWT_SECRET: process.env.JWT_SECRET as string,
  };
};

export const envVars = loadEnvVariables();
