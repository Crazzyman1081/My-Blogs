"use client";

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { FaGithub, FaLinkedin, FaFlag, FaHome, FaUserSecret, FaUsers, FaBook, FaPenNib } from 'react-icons/fa';
import styles from './Sidebar.module.css';

const Sidebar = () => {
    const pathname = usePathname();
    const basePath = process.env.NODE_ENV === 'production' ? '/My-Blogs' : '';

    return (
        <aside className={styles.sidebar}>
            <div className={styles.profile}>
                <div className={styles.avatarContainer}>
                    <img
                        src={`${basePath}/pfp.jpg`}
                        alt="Shona"
                        className={styles.avatar}
                    />
                </div>
                <div className={styles.profileInfo}>
                    <h2>Crazzyman1081</h2>
                    <p>Reverse Engineer</p>
                </div>
            </div>

            <nav className={styles.nav}>
                <Link href="/" className={`${styles.navItem} ${pathname === '/' ? styles.active : ''}`}>
                    <span className={styles.icon}><FaHome /></span> Home
                </Link>
                <Link href="/writeups" className={`${styles.navItem} ${pathname === '/writeups' ? styles.active : ''}`}>
                    <span className={styles.icon}><FaBook /></span> Writeups
                </Link>
                <Link href="/blogs" className={`${styles.navItem} ${pathname === '/blogs' ? styles.active : ''}`}>
                    <span className={styles.icon}><FaPenNib /></span> Blogs
                </Link>
                <Link href="/about" className={`${styles.navItem} ${pathname === '/about' ? styles.active : ''}`}>
                    <span className={styles.icon}><FaUserSecret /></span> About Me
                </Link>
            </nav>

            <div className={styles.team}>
                Member of <a href="https://0bscuri7y.xyz" target="_blank" rel="noopener noreferrer" className={styles.teamLink}>0bscuri7y</a>
            </div>

            <div className={styles.socials}>
                <a href="https://github.com/Crazzyman1081" target="_blank" rel="noopener noreferrer" aria-label="Github" className={styles.socialIcon}><FaGithub /></a>
                <a href="https://www.linkedin.com/in/rishabhsz/" target="_blank" rel="noopener noreferrer" aria-label="LinkedIn" className={styles.socialIcon}><FaLinkedin /></a>
                <a href="https://ctftime.org/user/216877" target="_blank" rel="noopener noreferrer" aria-label="CTFTime" className={styles.socialIcon}><FaFlag /></a>
                <a href="https://ctftime.org/team/370140" target="_blank" rel="noopener noreferrer" aria-label="Team 0bscuri7y" className={styles.socialIcon} title="Team 0bscuri7y"><FaUsers /></a>
            </div>
        </aside>
    );
};

export default Sidebar;
