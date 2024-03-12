import { PrismaClient, RoleType } from '@prisma/client';
const prisma = new PrismaClient();

async function resetAutoIncrement() {
  await prisma.$executeRaw`ALTER SEQUENCE "Role_id_seq" RESTART WITH 1`;
}

const roles = [
  {
    name: RoleType.Customer,
  },
  {
    name: RoleType.Seller,
  },
];

async function main() {
  // Remove this for production
  await resetAutoIncrement();

  for (const roleData of roles) {
    const role = await prisma.role.create({
      data: {
        name: roleData.name,
      },
    });

    console.log(`Role created: ${role.name}`);
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
