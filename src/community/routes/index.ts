import { Router } from 'express';
import communityRoutes from './community.route';
import projectRoutes from './project.routes';
import taskRoutes from './task.routes';

const router = Router();

// Mount all routes
router.use('/', communityRoutes);
router.use('/', projectRoutes);
router.use('/', taskRoutes);

export default router;
