import styles from '../posts/[slug]/post.module.css';

export default function About() {
    return (
        <div className={styles.container}>
            <div className={styles.header}>
                <h1 className={styles.title}>About Me</h1>
            </div>

            <div className={styles.content}>
                <p>
                    Hey! I'm Crazzyman1081. I'm a Reverse Engineer and CTF player.
                </p>
                <p>
                    I play with <a href="https://ctftime.org/team/370140" target="_blank" rel="noopener noreferrer">0bscuri7y</a>.
                </p>

                <h2>My Interests</h2>
                <ul>
                    <li>Reverse Engineering</li>
                    <li>Malware Analysis</li>
                    <li>DFIR</li>
                    <li>OSINT</li>
                    <li>Vibe Pwning</li>
                </ul>

                <h2>Contact</h2>
                <p>
                    You can find me on Twitter, Discord, and LinkedIn.
                    Check the sidebar for links!
                </p>
            </div>
        </div>
    );
}
