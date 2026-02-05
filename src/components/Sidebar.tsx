"use client";

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState } from 'react';
import { FaGithub, FaLinkedin, FaFlag, FaHome, FaUserSecret, FaUsers, FaBook, FaPenNib } from 'react-icons/fa';
import styles from './Sidebar.module.css';

const Sidebar = () => {
    const pathname = usePathname();
    const basePath = '';

    const [isOpen, setIsOpen] = useState(false);

    const toggleMenu = () => {
        setIsOpen(!isOpen);
    };

    const closeMenu = () => {
        setIsOpen(false);
    }

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

            {/* Hamburger Icon */}
            <button className={styles.hamburger} onClick={toggleMenu} aria-label="Toggle menu">
                <span style={{ transform: isOpen ? 'rotate(45deg) translate(5px, 5px)' : 'none' }}></span>
                <span style={{ opacity: isOpen ? 0 : 1 }}></span>
                <span style={{ transform: isOpen ? 'rotate(-45deg) translate(5px, -5px)' : 'none' }}></span>
            </button>

            <nav className={`${styles.nav} ${isOpen ? styles.open : ''}`}>
                <Link href="/" className={`${styles.navItem} ${pathname === '/' ? styles.active : ''}`} onClick={closeMenu}>
                    <span className={styles.icon}><FaHome /></span> Home
                </Link>
                <Link href="/writeups" className={`${styles.navItem} ${pathname === '/writeups' ? styles.active : ''}`} onClick={closeMenu}>
                    <span className={styles.icon}><FaBook /></span> Writeups
                </Link>
                <Link href="/blogs" className={`${styles.navItem} ${pathname === '/blogs' ? styles.active : ''}`} onClick={closeMenu}>
                    <span className={styles.icon}><FaPenNib /></span> Blogs
                </Link>
                <Link href="/about" className={`${styles.navItem} ${pathname === '/about' ? styles.active : ''}`} onClick={closeMenu}>
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
