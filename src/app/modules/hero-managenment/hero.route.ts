import express from 'express';
import { HeroController } from './hero.controller';
import { auth } from '../../middleware/auth';

const router = express.Router();

// Public
router.get('/', HeroController.getAllHero);
router.get('/:id', HeroController.getSingleHero);

// Admin only
router.post('/', auth('ADMIN'), HeroController.createHero);
router.patch('/:id', auth('ADMIN'), HeroController.updateHero);
router.delete('/:id', auth('ADMIN'), HeroController.deleteHero);

export const HeroRoutes = router;

// POST    /api/v1/hero        (ADMIN)
// GET     /api/v1/hero        (PUBLIC)
// GET     /api/v1/hero/:id    (PUBLIC)
// PATCH   /api/v1/hero/:id    (ADMIN)
// DELETE  /api/v1/hero/:id    (ADMIN)
