import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { listTeams, createTeam, addMember, deleteTeam } from '../controllers/teams.controller.js';

const router = Router();

router.use(requireAuth);

router.get('/', listTeams);

router.post('/', createTeam);

router.post('/:teamId/members', addMember);

router.delete('/:teamId', deleteTeam);

export default router;
