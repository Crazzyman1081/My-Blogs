"use client";

import { useEffect, useState } from 'react';
import styles from './TableOfContents.module.css';

interface TOCProps {
    headings: { id: string; text: string; level: number }[];
}

const TableOfContents = ({ headings }: TOCProps) => {
    const [activeId, setActiveId] = useState<string>('');

    useEffect(() => {
        const observer = new IntersectionObserver(
            (entries) => {
                entries.forEach((entry) => {
                    if (entry.isIntersecting) {
                        setActiveId(entry.target.id);
                    }
                });
            },
            { rootMargin: '0px 0px -80% 0px' }
        );

        headings.forEach(({ id }) => {
            const element = document.getElementById(id);
            if (element) observer.observe(element);
        });

        return () => observer.disconnect();
    }, [headings]);

    if (headings.length === 0) return null;

    return (
        <nav className={styles.toc}>
            <h3 className={styles.title}>On this page</h3>
            <ul className={styles.list}>
                {headings.map(({ id, text, level }) => (
                    <li key={id} className={`${styles.item} ${styles[`level-${level}`]}`}>
                        <a
                            href={`#${id}`}
                            className={`${styles.link} ${activeId === id ? styles.active : ''}`}
                            onClick={(e) => {
                                e.preventDefault();
                                document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' });
                                setActiveId(id);
                            }}
                        >
                            {text}
                        </a>
                    </li>
                ))}
            </ul>
        </nav>
    );
};

export default TableOfContents;
