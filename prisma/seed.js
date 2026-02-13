// Plain JavaScript seed script using Prisma Client
const { PrismaClient, UserRole, BatchStatus } = require('../generated/prisma');

const prisma = new PrismaClient();

async function main() {
  // Create base users
  const admin = await prisma.user.upsert({
    where: { email: 'admin@example.com' },
    update: {},
    create: {
      fullName: 'Super Admin',
      email: 'admin@example.com',
      passwordHash: 'CHANGE_ME', // TODO: replace with real hash
      role: UserRole.SUPER_ADMIN,
    },
  });

  const counselor = await prisma.user.upsert({
    where: { email: 'counselor@example.com' },
    update: {},
    create: {
      fullName: 'Primary Counselor',
      email: 'counselor@example.com',
      passwordHash: 'CHANGE_ME', // TODO: replace with real hash
      role: UserRole.COUNSELOR,
    },
  });

  // Create a sample course and batch
  const course = await prisma.course.upsert({
    where: { code: 'FSD-2024' },
    update: {},
    create: {
      name: 'Full Stack Development',
      code: 'FSD-2024',
      baseFee: 100000.0,
    },
  });

  const batch = await prisma.batch.create({
    data: {
      name: 'Batch A - Morning',
      courseId: course.id,
      startDate: new Date(),
      maxSeats: 30,
      status: BatchStatus.OPEN,
    },
  });

  // eslint-disable-next-line no-console
  console.log('Seed data created:', { admin, counselor, course, batch });
}

main()
  .catch((e) => {
    // eslint-disable-next-line no-console
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

