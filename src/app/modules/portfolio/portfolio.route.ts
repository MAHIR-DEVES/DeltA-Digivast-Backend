import express from 'express';
import { PortfolioController } from './portfolio.controller';
import { auth } from '../../middleware/auth';

const router = express.Router();

// Public
router.get('/', PortfolioController.getAllPortfolio);
router.get('/:id', PortfolioController.getSinglePortfolio);

// Admin only
router.post('/', auth('ADMIN'), PortfolioController.createPortfolio);
router.patch('/:id', auth('ADMIN'), PortfolioController.updatePortfolio);
router.delete('/:id', auth('ADMIN'), PortfolioController.deletePortfolio);

export const PortfolioRoutes = router;

// POST    /api/v1/portfolio        (ADMIN)
// GET     /api/v1/portfolio        (PUBLIC)
// GET     /api/v1/portfolio/:id    (PUBLIC)
// PATCH   /api/v1/portfolio/:id    (ADMIN)
// DELETE  /api/v1/portfolio/:id    (ADMIN)
