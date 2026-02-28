import { Router } from 'express';
import { UserRoute } from '../modules/user/user.route';

const router = Router();

router.use('/users', UserRoute);

export const IndexRoutes = router;
