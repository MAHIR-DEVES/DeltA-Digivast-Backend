import { prisma } from '../../lib/prisma';

interface IHeroData {
  title: string;
  description: string;
  imageUrl: string;
}

const createHero = async (payload: IHeroData) => {
  return await prisma.hero.create({
    data: payload,
  });
};

const getAllHero = async () => {
  return await prisma.hero.findMany({
    orderBy: {
      createdAt: 'desc',
    },
  });
};

const getSingleHero = async (id: string) => {
  return await prisma.hero.findUnique({
    where: { id },
  });
};

const updateHero = async (id: string, payload: Partial<IHeroData>) => {
  return await prisma.hero.update({
    where: { id },
    data: payload,
  });
};

const deleteHero = async (id: string) => {
  return await prisma.hero.delete({
    where: { id },
  });
};

export const HeroService = {
  createHero,
  getAllHero,
  getSingleHero,
  updateHero,
  deleteHero,
};
