import { CommunityRole } from '@prisma/client';

// Error Classes
export class NotFoundException extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NotFoundException';
  }
}

export class UnauthorizedException extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnauthorizedException';
  }
}

// Task Status Enum
export enum TaskStatusEnum {
  BACKLOG = 'BACKLOG',
  TODO = 'TODO',
  IN_PROGRESS = 'IN_PROGRESS',
  IN_REVIEW = 'IN_REVIEW',
  DONE = 'DONE'
}

// Task Priority Enum
export enum TaskPriorityEnum {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  URGENT = 'URGENT'
}

// Role and Permission Enums
export enum Permissions {
  CREATE_WORKSPACE = 'CREATE_WORKSPACE',
  EDIT_WORKSPACE = 'EDIT_WORKSPACE',
  DELETE_WORKSPACE = 'DELETE_WORKSPACE',
  MANAGE_WORKSPACE_SETTINGS = 'MANAGE_WORKSPACE_SETTINGS',
  ADD_MEMBER = 'ADD_MEMBER',
  CHANGE_MEMBER_ROLE = 'CHANGE_MEMBER_ROLE',
  REMOVE_MEMBER = 'REMOVE_MEMBER',
  CREATE_PROJECT = 'CREATE_PROJECT',
  EDIT_PROJECT = 'EDIT_PROJECT',
  DELETE_PROJECT = 'DELETE_PROJECT',
  CREATE_TASK = 'CREATE_TASK',
  EDIT_TASK = 'EDIT_TASK',
  DELETE_TASK = 'DELETE_TASK',
  VIEW_ONLY = 'VIEW_ONLY',
  UPDATE_TASK = 'UPDATE_TASK',
  ASSIGN_TASK = 'ASSIGN_TASK',
}

export type RoleType = 'OWNER' | 'ADMIN' | 'MANAGER' | 'DEVELOPER I' | 'DEVELOPER II' | 'DEVELOPER III';
export type PermissionType = keyof typeof Permissions;

// Role Permissions Mapping
export const RolePermissions: Record<RoleType, Array<PermissionType>> = {
  OWNER: [
    Permissions.CREATE_WORKSPACE,
    Permissions.EDIT_WORKSPACE,
    Permissions.DELETE_WORKSPACE,
    Permissions.MANAGE_WORKSPACE_SETTINGS,
    Permissions.ADD_MEMBER,
    Permissions.CHANGE_MEMBER_ROLE,
    Permissions.REMOVE_MEMBER,
    Permissions.CREATE_PROJECT,
    Permissions.EDIT_PROJECT,
    Permissions.DELETE_PROJECT,
    Permissions.CREATE_TASK,
    Permissions.EDIT_TASK,
    Permissions.DELETE_TASK,
    Permissions.VIEW_ONLY,
  ],
  ADMIN: [
    Permissions.ADD_MEMBER,
    Permissions.CREATE_PROJECT,
    Permissions.EDIT_PROJECT,
    Permissions.DELETE_PROJECT,
    Permissions.CREATE_TASK,
    Permissions.EDIT_TASK,
    Permissions.DELETE_TASK,
    Permissions.MANAGE_WORKSPACE_SETTINGS,
    Permissions.VIEW_ONLY,
  ],
  MANAGER: [
    Permissions.CREATE_PROJECT,
    Permissions.EDIT_PROJECT,
    Permissions.CREATE_TASK,
    Permissions.EDIT_TASK,
    Permissions.DELETE_TASK,
    Permissions.VIEW_ONLY,
  ],
  'DEVELOPER I': [
    Permissions.VIEW_ONLY,
    Permissions.CREATE_TASK,
    Permissions.EDIT_TASK,
  ],
  'DEVELOPER II': [
    Permissions.VIEW_ONLY,
    Permissions.CREATE_TASK,
    Permissions.EDIT_TASK,
    Permissions.DELETE_TASK,
  ],
  'DEVELOPER III': [
    Permissions.VIEW_ONLY,
    Permissions.CREATE_TASK,
    Permissions.EDIT_TASK,
    Permissions.DELETE_TASK,
    Permissions.EDIT_PROJECT,
  ],
};

// Map Prisma CommunityRole to our RoleType
const roleMapping: Record<CommunityRole, RoleType> = {
  [CommunityRole.OWNER]: 'OWNER',
  [CommunityRole.ADMIN]: 'ADMIN',
  [CommunityRole.MANAGER]: 'MANAGER',
  [CommunityRole.DEVELOPER_I]: 'DEVELOPER I',
  [CommunityRole.DEVELOPER_II]: 'DEVELOPER II',
  [CommunityRole.DEVELOPER_III]: 'DEVELOPER III',
  [CommunityRole.VIEWER]: 'DEVELOPER I'
};

export const roleGuard = (role: CommunityRole | undefined, requiredPermissions: PermissionType[]) => {
  if (!role) {
    throw new UnauthorizedException('Unauthorized');
  }

  const mappedRole = roleMapping[role];
  const permissions = RolePermissions[mappedRole];

  const hasPermission = requiredPermissions.every(permission => 
    permissions.includes(permission)
  );

  if (!hasPermission) {
    throw new UnauthorizedException('Insufficient permissions');
  }
};
