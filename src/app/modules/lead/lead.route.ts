import express from 'express';
import { LeadController } from './lead.controller';
import { auth } from '../../middleware/auth';

const router = express.Router();

// Public (frontend form submit করবে)
router.post('/', LeadController.createLead);

// Admin Only
router.get('/', auth('ADMIN'), LeadController.getAllLeads);
router.get('/:id', auth('ADMIN'), LeadController.getSingleLead);
router.delete('/:id', auth('ADMIN'), LeadController.deleteLead);

export const LeadRoutes = router;

// POST    /api/v1/leads        (PUBLIC - form submit)
// GET     /api/v1/leads        (ADMIN)
// GET     /api/v1/leads/:id    (ADMIN)
// DELETE  /api/v1/leads/:id    (ADMIN)
