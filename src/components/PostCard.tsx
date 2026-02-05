import Link from 'next/link';
import styles from './PostCard.module.css';

interface PostCardProps {
    id: string;
    title: string;
    date: string;
    excerpt?: string;
    coverImage?: string;
    variant?: 'default' | 'large';
}

const PostCard = ({ id, title, date, excerpt, coverImage, variant = 'default' }: PostCardProps) => {
    return (
        <Link href={`/posts/${id}`} className={`${styles.card} ${variant === 'large' ? styles.cardLarge : ''}`}>
            {coverImage && (
                <div className={`${styles.imageContainer} ${variant === 'large' ? styles.imageContainerLarge : ''}`}>
                    <img src={coverImage} alt={title} className={styles.image} />
                </div>
            )}
            <div className={styles.content}>
                <h3 className={styles.title}>{title}</h3>
                <div className={styles.date}>{date}</div>
                {excerpt && <p className={styles.excerpt}>{excerpt}</p>}
            </div>
        </Link>
    );
};

export default PostCard;
