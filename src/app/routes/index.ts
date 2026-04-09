import { Router } from 'express';
import { UserRoute } from '../modules/user/user.route';
import { BlogRoutes } from '../modules/blog/blog.route';
import { HeroRoutes } from '../modules/hero-managenment/hero.route';
import { PortfolioRoutes } from '../modules/portfolio/portfolio.route';
import { LeadRoutes } from '../modules/lead/lead.route';
import { CourseRoutes } from '../modules/course/course.route';
import { AttendanceRoutes } from '../modules/attendance/attendance.route';
import { StatsRoutes } from '../modules/stats/stats.route';
import { paymentRoutes } from '../modules/payment/payment.route';

const router = Router();

router.use('/users', UserRoute);
router.use('/blogs', BlogRoutes);
router.use('/hero', HeroRoutes);
router.use('/portfolio', PortfolioRoutes);
router.use('/leads', LeadRoutes);
router.use('/courses', CourseRoutes);
router.use('/attendance', AttendanceRoutes);
router.use('/stats', StatsRoutes);
router.use('/payment', paymentRoutes);

export default router;
