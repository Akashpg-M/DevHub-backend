import express from 'express';
import { z } from 'zod';
import { ProjectController } from '../controllers/project.controller';
import { protectRoute } from '../../auth_app/middleware/auth.middleware';
import { validateRequest } from '../../auth_app/middleware/validation.middleware';
import { asyncHandler } from '../../utils/asyncHandler';

const router = express.Router();
const projectController = new ProjectController();

// Validation schemas
const createProjectSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  emoji: z.string().optional(),
});

const updateProjectSchema = createProjectSchema;

// Project CRUD routes
router.post(
  '/:communityId/project',
  protectRoute,
  validateRequest({
    body: createProjectSchema,
    params: z.object({
      communityId: z.string()
    })
  }),
  asyncHandler(projectController.createProject.bind(projectController))
);

router.get(
  '/:communityId/project',
  protectRoute,
  validateRequest({
    params: z.object({
      communityId: z.string()
    })
  }),
  asyncHandler(projectController.getProjectsInCommunity.bind(projectController))
);

router.get(
  '/:communityId/project/:projectId',
  protectRoute,
  validateRequest({
    params: z.object({
      communityId: z.string(),
      projectId: z.string()
    })
  }),
  asyncHandler(projectController.getProjectByIdAndCommunityId.bind(projectController))
);

router.get(
  '/:communityId/project/:projectId/analytics',
  protectRoute,
  // authorizeRole([UserRole.ADMIN], [CommunityRole.OWNER, CommunityRole.ADMIN]),
  validateRequest({
    params: z.object({
      communityId: z.string(),
      projectId: z.string()
    })
  }),
  projectController.getProjectAnalytics.bind(projectController)
);

router.get(
  '/:communityId/project/:projectId/members',
  protectRoute,
  validateRequest({
    params: z.object({
      communityId: z.string(),
      projectId: z.string()
    })
  }),
  projectController.getProjectMembers.bind(projectController)
);

// Project member management
router.post(
  '/:communityId/project/:projectId/join',
  protectRoute,
  validateRequest({
    params: z.object({
      communityId: z.string(),
      projectId: z.string()
    })
  }),
  projectController.joinProject.bind(projectController)
);

router.post(
  '/:communityId/project/:projectId/leave',
  protectRoute,
  validateRequest({
    params: z.object({
      communityId: z.string(),
      projectId: z.string()
    })
  }),
  projectController.leaveProject.bind(projectController)
);

// Project management
router.patch(
  '/:communityId/project/:projectId',
  protectRoute,
  validateRequest({
    params: z.object({
      communityId: z.string(),
      projectId: z.string()
    }),
    body: updateProjectSchema
  }),
  asyncHandler(projectController.updateProject.bind(projectController))
);

router.delete(
  '/:communityId/project/:projectId',
  protectRoute,
  validateRequest({
    params: z.object({
      communityId: z.string(),
      projectId: z.string()
    })
  }),
  asyncHandler(projectController.deleteProject.bind(projectController))
);

export default router;
